# auto-ropper
Auto-ropper is a tool that aims to automate the exploitation of ROP. Its goal is to become a tool that no longer requires user interaction.

# Installation
You need :
* [Python 3](https://www.python.org/)
* [pwntools](https://docs.pwntools.com/en/stable/)
* [BeautifulSoup](https://pypi.org/project/beautifulsoup4/)

## With pip
Just do:
```
$ pip install pwn
$ pip install beautifulsoup4
```

# Usage
Before starting the program, you'll have to do the following:
```bash
sudo sysctl -w kernel.core_pattern=core
```
This will allow the core file to be generated as `core` (this won't survive a restart).<br>
<br>
Then, you have to edit the binary location and name.
```py
elf = ELF("./tests/ret") # edit the PATH to your binary location.
```
Then, you can run it.<br>

Once it's done, restart the program and you should have a shell. Happy hacking! :-) 

# Didn't pwned...
There can be various reasons as to why you didn't got a shell. The first one being, it didn't leaked the address correctly. You should try to run again the program (it happens during test, this is the only "fix" i found)<br>
Another reason can be it either didn't found a libc, or the libc doesn't seem pwnable<br>
The last reason is, you might just try to pwn something that is either not pwnable or that my tool can't pwn!

# Contributing
Thanks to for helping me in this project:<br>
@Red-Amber
@Tim-ats-d
