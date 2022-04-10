import logging
from pwn import *
import argparse
from utils.gui import Gui
from utils.exploit import Exploit
import os

context.log_level = 'error'
logging.basicConfig()
logging.root.setLevel(logging.INFO)

loud_loggers = ["angr.engines", "angr.sim_manager", "angr.simos", "angr.project", "angr.procedures", "cle", "angr.storage"]
for loud_logger in loud_loggers:
	logging.getLogger(loud_logger).setLevel(logging.ERROR)

logging.getLogger("angr.project").disabled=True

log = logging.getLogger(__name__)

if __name__ == "__main__":
	if os.path.exists(os.path.join(os.getcwd(), "libc")) == False:
		os.makedirs(os.path.join(os.getcwd(), "libc"))
	if os.path.exists(os.path.join(os.getcwd(), "database")) == False:
		os.makedirs(os.path.join(os.getcwd(), "database"))
	if os.path.exists(os.path.join(os.getcwd()+"/database/", "database")) == False:
		open('./database/database',"x")
	#if sys.argv[1] == "": raise ValueError("Please provide a type of attack (local, remote, gui)")
	
	parser = argparse.ArgumentParser(
		description='Auto-ropper is a tool that aims to automate the exploitation of ROPchain.'
		)

	mode = parser.add_subparsers(title="mode")

	local_attack = mode.add_parser("local", parents=[parser], add_help=False, description="For local pwning")
	local_attack.add_argument("-b","--binary",help="Path to binary")
	local_attack.add_argument("-a","--arch",help="Arch on which the binary is. Default is amd64.\n 'aarch64': {'bits': 64, 'endian': 'little'}\n 'alpha': {'bits': 64, 'endian': 'little'}\n 'amd64': {'bits': 64, 'endian': 'little'}\n 'arm': {'bits': 32, 'endian': 'little'}\n 'avr': {'bits': 8, 'endian': 'little'}\n 'cris': {'bits': 32, 'endian': 'little'}\n 'i386': {'bits': 32, 'endian': 'little'}\n 'ia64': {'bits': 64, 'endian': 'big'}\n 'm68k': {'bits': 32, 'endian': 'big'}\n 'mips': {'bits': 32, 'endian': 'little'}\n 'mips64': {'bits': 64, 'endian': 'little'}\n 'msp430': {'bits': 16, 'endian': 'little'}\n 'none': {}, 'powerpc': {'bits': 32, 'endian': 'big'}\n 'powerpc64': {'bits': 64, 'endian': 'big'}\n 'riscv': {'bits': 32, 'endian': 'little'}\n 's390': {'bits': 32, 'endian': 'big'}\n 'sparc': {'bits': 32, 'endian': 'big'}\n 'sparc64': {'bits': 64, 'endian': 'big'}\n 'thumb': {'bits': 32, 'endian': 'little'}\n 'vax': {'bits': 32, 'endian': 'little'}")
	local_attack.add_argument("-z","--printable",help="Constrain input to be printable")
	local_attack.set_defaults(which="local")
	
	remote_attack = mode.add_parser("remote", parents=[parser], add_help=False, description="For remote pwning")
	remote_attack.add_argument("-b","--binary",help="Path to binary")
	remote_attack.add_argument("-a","--arch",help="Arch on which the binary is")
	remote_attack.add_argument("-z","--printable",help="Constrain input to be printable")
	remote_attack.add_argument("-i","--ip",help="IP of remote victim")
	remote_attack.add_argument("-p","--port",help="Port of remote victim")
	remote_attack.set_defaults(which="remote")

	gui = mode.add_parser("gui", parents=[parser], add_help=False, description="Launch GUI")
	gui.set_defaults(which="gui")

	args = parser.parse_args()
	
	if args.which == "gui":
		Gui()
	
	elif not args.binary:
		log.warning("No binary given... Please provide one.")
		exit(0)

	attack = Exploit({k:v for k,v in args.__dict__.items() if v is not None})
	attack.main()
