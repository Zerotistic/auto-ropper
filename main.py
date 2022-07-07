# pyright: reportMissingImports=false, reportUndefinedVariable=false
from pwn import *
import logging
import argparse
import os

from utils.pwner import Pwner
from utils.gui import Gui
context.log_level = 'error'
logging.basicConfig()
logging.root.setLevel(logging.INFO)
loud_loggers = [
	"angr.engines", "angr.sim_manager", "angr.simos", "angr.project", 
	"angr.procedures", "cle", "angr.storage", "pwnlib.elf.elf", 
	"pwnlib.tubes", "pwnlib.rop.rop"
	]
for loud_logger in loud_loggers:
	logging.getLogger(loud_logger).setLevel(logging.ERROR)

logging.getLogger("angr.project").disabled=True

log = logging.getLogger(__name__)

def is_radare_installed():
	return which("r2") is not None

def is_64bit_elf(binary):
	with open(binary, "rb") as f:
		if f.read(5)[-1] != 2:
			log.warning("Binary is not ELF 64bit. This will not work. Please use a 64bit binary.")
			exit(0)
		f.close()
if __name__ == "__main__":
	parser = argparse.ArgumentParser(
		description='pwn is annoying so i made a tool to do it for me'
		)

	mode = parser.add_subparsers(title="mode")

	local_attack = mode.add_parser("local", parents=[parser], add_help=False, description="For local pwning")
	local_attack.add_argument("-b","--binary",help="Path to binary")
	local_attack.add_argument("-a","--arch",help="Arch on which the binary is. Default is amd64.")
	local_attack.add_argument("-z","--printable",help="Constrain input to be printable")
	local_attack.set_defaults(which="local")
	
	remote_attack = mode.add_parser("remote", parents=[parser], add_help=False, description="For remote pwning")
	remote_attack.add_argument("-b","--binary",help="Path to binary")
	remote_attack.add_argument("-a","--arch",help="Arch on which the binary is")
	remote_attack.add_argument("-z","--printable",help="Constrain input to be printable")
	remote_attack.add_argument("-i","--ip",help="IP of remote victim")
	remote_attack.add_argument("-p","--port",help="Port of remote victim")
	remote_attack.set_defaults(which="remote")

	ssh_attack = mode.add_parser("ssh", parents=[parser], add_help=False, description="For remote pwning via ssh")
	ssh_attack.add_argument("-b","--binary",help="Path to binary")
	ssh_attack.add_argument("-a","--arch",help="Arch on which the binary is")
	ssh_attack.add_argument("-z","--printable",help="Constrain input to be printable")
	ssh_attack.add_argument("-i","--ip",help="ssh IP of remote victim")
	ssh_attack.add_argument("-p","--port",help="Port of victim's ssh (default: 22)", default=22)
	ssh_attack.add_argument("-u","--username",help="Username of victim's ssh")
	ssh_attack.add_argument("-pw","--password",help="Password of victim's ssh")
	ssh_attack.set_defaults(which="ssh")

	gui = mode.add_parser("gui", parents=[parser], add_help=False, description="Launch GUI")
	gui.set_defaults(which="gui")

	args = parser.parse_args()

	if os.path.exists(os.path.join(os.getcwd(), "libc")) == False:
		os.makedirs(os.path.join(os.getcwd(), "libc"))
	
	if not is_radare_installed():
		log.warning("Error radare2 is not installed. Please do: sudo apt install radare2")
		exit(1)

	if args.which == "gui":
		Gui()
		exit(0)

	elif not args.binary:
		log.warning("No binary given... Please provide one.")
		exit(0)
	else:
		is_64bit_elf(args.binary)
	
	pwner = Pwner(vars(args))
	pwner.main()
