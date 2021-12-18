# Auto-Ropper
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
help page
```
usage: rop.py [-h] {local,remote,gui} ...

Auto-ropper is a tool that aims to automate the exploitation of ROP.

optional arguments:
  -h, --help          show this help message and exit

mode:
  {local,remote,gui}
```

Once it's done, restart the program and you should have a shell. Happy hacking! :-) 

# Didn't pwned...
There can be various reasons as to why you didn't got a shell. 
1) The first one being, it didn't leaked the address correctly. You should try to run again the program 
2) Another reason can be it either didn't found a libc, or the libc doesn't seem pwnable
3) The last reason is, you might just try to pwn something that is either not pwnable or that my tool can't pwn!

# Bugs / Update
If you were to find a bug, please do create an issue.<br>
If you want to add something, you can fork an create a push request, or you can create an issue. If it is an issue, i might take some time, or refuse to do it myself. 
# Contributing
Thanks to those people for helping me in this project:<br>
@Red-Amber
@Tim-ats-d
