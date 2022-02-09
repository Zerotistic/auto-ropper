import tkinter as tk
import tkinter.font as tkFont
import tkinter.messagebox 
from tkinter.filedialog import askopenfilename

from exploit import Exploit

class Gui(Exploit):
	def __init__(self, root):
		self.root = root
		self.args = {"is_printable_var": False, "binary_path": None, "libc_path": None, "mode": "local"}
		self.main()

	def main(self):
		self.root.title("GUI")
		width=228
		height=311
		screenwidth = self.root.winfo_screenwidth()
		screenheight = self.root.winfo_screenheight()
		alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
		self.root.geometry(alignstr)
		self.root.resizable(width=False, height=False)

		brn_run=tk.Button(self.root)
		brn_run["bg"] = "#efefef"
		ft = tkFont.Font(family='Times',size=10)
		brn_run["font"] = ft
		brn_run["fg"] = "#000000"
		brn_run["justify"] = "center"
		brn_run["text"] = "Run"
		brn_run.place(x=80,y=250,width=70,height=25)
		brn_run["command"] = self.btn_run_exec

		btn_bin=tk.Button(self.root)
		btn_bin["bg"] = "#efefef"
		ft = tkFont.Font(family='Times',size=10)
		btn_bin["font"] = ft
		btn_bin["fg"] = "#000000"
		btn_bin["justify"] = "center"
		btn_bin["text"] = "Binary"
		btn_bin.place(x=30,y=20,width=177,height=30)
		btn_bin["command"] = self.btn_bin_exec

		btn_libc=tk.Button(self.root)
		btn_libc["bg"] = "#efefef"
		ft = tkFont.Font(family='Times',size=10)
		btn_libc["font"] = ft
		btn_libc["fg"] = "#000000"
		btn_libc["justify"] = "center"
		btn_libc["text"] = "libc (optional)"
		btn_libc.place(x=30,y=60,width=176,height=30)
		btn_libc["command"] = self.btn_libc_exec

		isPrintable=tk.Checkbutton(self.root)
		ft = tkFont.Font(family='Times',size=10)
		isPrintable["font"] = ft
		isPrintable["fg"] = "#333333"
		isPrintable["justify"] = "center"
		isPrintable["text"] = ""
		isPrintable.place(x=140,y=120,width=78,height=30)
		isPrintable["offvalue"] = "0"
		isPrintable["onvalue"] = "1"
		isPrintable["command"] = self.checkbox_printable

		msg_printable=tk.Message(self.root)
		ft = tkFont.Font(family='Times',size=10)
		msg_printable["font"] = ft
		msg_printable["fg"] = "#333333"
		msg_printable["justify"] = "center"
		msg_printable["text"] = "printable payload"
		msg_printable.place(x=30,y=120,width=109,height=30)

		self.var_mode = tk.StringVar(self.root)
		self.var_mode.set("local") 
		dd_mode = tk.OptionMenu(self.root, self.var_mode, "local", "remote", "ssh",command=lambda var: self.set_mode(var))
		dd_mode["borderwidth"] = "1px"
		ft = tkFont.Font(family='Times',size=10)
		dd_mode["font"] = ft
		dd_mode["fg"] = "#333333"
		dd_mode["justify"] = "center"
		dd_mode.place(x=30,y=170,width=180,height=30) 

	def set_mode(self, var):
		self.args["mode"] = var
		if self.args["mode"] == "remote":
			self.remote_mode()
		elif self.args["mode"] == "ssh":
			self.ssh_mode()
		elif self.args["mode"] == "local":
			self.clean_mode()
	# to fix
	def remote_mode(self):
		self.ipvar = tk.StringVar()
		self.portvar = tk.StringVar()
		ip = tk.Entry(master=self.root, textvariable=self.ipvar, width = 10)
		ip.pack(padx=0, pady=195)
		port = tk.Entry(master=self.root, textvariable=self.portvar, width = 5)
		port.pack(padx=150, pady=205)
		print(f"{self.ipvar.get()}{self.portvar.get()}")

	def clean_mode(self):
		pass

	def ssh_mode(self):
		pass

	def btn_run_exec(self):
		if not self.args["bin_path"]: tkinter.messagebox.showinfo("Error cannot run",  "Please add a binary")
		elif not self.args["mode"] : tkinter.messagebox.showinfo("Error cannot run",  "Please add a mode (local, remote, ssh)")
		attack = Exploit({k:v for k,v in self.args.__dict__.items() if v is not None})
		attack.main()

	def btn_bin_exec(self):
		self.args["bin_path"] = askopenfilename()

	def btn_libc_exec(self):
		self.args["libc_path"] = askopenfilename()

	def checkbox_printable(self):
		self.args["is_printable_var"] = not self.is_printable_var
