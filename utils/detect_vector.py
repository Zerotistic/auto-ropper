# pyright: reportMissingImports=false, reportUndefinedVariable=false
from pwn import *
import angr
import claripy
import timeout_decorator
from angr import sim_options as so


class Dectect_vector():
	def __init__(self, binary, is_printable):
		self.info = {}
		self.info["is_printable"] = is_printable
		self.info["binary"] = binary

	def detect(self):
		log.info("Determining input type and attack vector...")
		# check if input is stdin or arg
		self.info["input_type"] = self.input_type()
		# check attack vector
		self.info["pwn_type"], self.info["offset"] = self.pwn_type()
		log.info(f"Input type is {self.info['input_type']} and attack vector is {self.info['pwn_type']}")
		log.info(f"Found offset: {self.info['offset']}")
		return self.info

	def input_type(self):
		elf = ELF(self.info["binary"])
		for name in elf.got.keys():
			if name in ["gets", "fgets", "scanf", "fscanf", "getchar", "fgetc", "getc", "__isoc99_scanf", "read"]:
				return "STDIN"
			else: pass
		return "ARG"

	def pwn_type(self):
		pwn_type, offset = self.check_overflow(
			inputType = self.info["input_type"]
		)

		if not pwn_type:
			log.info("[+] Checking for format string pwn type...")
			pwn_type, offset = self.check_format(
				self.info["binary"], inputType = self.info["input_type"]
			)
		return pwn_type, offset


########################################################################
#																	   #
#																	   #
#		  EVERYTHING RELATED TO OVERFLOW DETECTION AND EXPLOIT 	   	   #
#																	   #
#																	   #
########################################################################

	def check_overflow(self, inputType):
		class hook_ret_four(angr.SimProcedure):
			IS_FUNCTION = True
			def run(self):
				return 4

		p = angr.Project(self.info["binary"], load_options={"auto_load_libs": False})
		p.hook_symbol("srand", hook_ret_four)
		p.hook_symbol("rand", hook_ret_four)

		more_options = {
			so.REVERSE_MEMORY_NAME_MAP,
			so.TRACK_ACTION_HISTORY,
			so.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
			so.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
		}

		argv = [self.info["binary"]]
		input_arg = claripy.BVS("input", 500 * 8)
		if inputType == "STDIN":
			state = p.factory.full_init_state(args=argv, stdin=input_arg)
			state.globals["input_stdin"] = input_arg
		elif inputType == "ARG":
			state = p.factory.full_init_state(args=argv, argc=1, argv=input_arg)
			state.globals["input_argv"] = input_arg
		else:
			argv.append(input_arg)
			state = p.factory.full_init_state(args=argv)
			state.globals["input_stdin"] = input_arg

		state.globals["input_type"] = inputType
		state.libc.buf_symbolic_bytes = 0x100
		simgr = p.factory.simgr(state, save_unconstrained=True)

		end_state = None
		env = {}
		env["offset"] = None

		try:
			@timeout_decorator.timeout(120)
			def search(simgr):
				simgr.explore(find=lambda s: "offset" in s.globals, step_func=self.overflow_detect_filter)
			search(simgr)
			if "found" in simgr.stashes and len(simgr.found):
				end_state = simgr.found[0]
				env["offset"] = end_state.globals["offset"]
		except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
			log.info("Keyboard interrupt or timeout. Exiting...")
		return "OVERFLOW", env["offset"]

	def overflow_detect_filter(self, simgr):
		for state in simgr.unconstrained:
			pc = b"A" * int(state.arch.bits / 8)
			if state.solver.satisfiable(extra_constraints=[state.regs.pc == pc]):
				state.add_constraints(state.regs.pc == pc)
				input_stdin = state.globals["input_stdin"]
				if self.info["is_printable"]:
					log.info("Making sure the payload is printable.")
					for c in input_stdin.chop(8):
						constraint = claripy.And(c > 0x2F, c < 0x7F)
						if state.solver.satisfiable([constraint]):
							state.add_constraints(constraint)
	
				num_bytes_input_crash = state.solver.eval(input_stdin, cast_to=bytes)
				state.globals["offset"] = num_bytes_input_crash.index(b"AAAA")
				state.globals["input"] = num_bytes_input_crash
				simgr.stashes["found"].append(state)
				simgr.stashes["unconstrained"].remove(state)
				break
		return simgr


########################################################################
#																	   #
#																	   #
#		  EVERYTHING RELATED TO FORMAT DETECTION AND EXPLOIT 	   	   #
#																	   #
#																	   #
########################################################################

	def check_format(self):
		# TO IMPLEMENT
		return "STRING FORMAT", None
