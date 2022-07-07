from utils.detect_vector import Dectect_vector
from utils.detect_overflow_type import Detect_overflow_type

from utils.overflow_ret2libc import Overflow_ret2libc
from utils.overflow_ret2win import Overflow_ret2win
from utils.string_format import String_format

from utils.gen_boilerplate import GenBoilerplate

from pwn import *

class Pwner(Overflow_ret2libc, Overflow_ret2win, String_format, Dectect_vector, Detect_overflow_type, GenBoilerplate):
	def __init__(self, args):
		self.args = args

	def main(self):
		detect_vector = Dectect_vector(self.args['binary'], self.args['printable'])
		info = detect_vector.detect()

		if info["pwn_type"] == "OVERFLOW":
			detect_overflow_type = Detect_overflow_type(info, self.args['binary'])
			overflow_type, info["exploit_info"] = detect_overflow_type.detect()
			log.info(f"Found overflow type {overflow_type}")
			if overflow_type == "RET2WIN":
				overflow_ret2win = Overflow_ret2win({k:v for k,v in self.args.items() if v is not None}, info["offset"], info["exploit_info"])
				result = overflow_ret2win.main()
			elif overflow_type == "RET2LIBC":
				overflow_ret2libc = Overflow_ret2libc({k:v for k,v in self.args.items() if v is not None}, info["offset"])
				result = overflow_ret2libc.main()

		elif info["pwn_type"] == "STRING FORMAT":
			string_format = String_format()
			result = string_format.main()

		if result != None or result != "":
			if result != "pwned":
				log.warning("Could not exploit... Creating boilerplate script")
				properties = {"binary":self.args['binary'], "offset":info["offset"], "pwn_type":info["pwn_type"]}
				gen_bp = GenBoilerplate(properties)
				gen_bp.main()