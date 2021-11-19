# auto-ropper
Auto-ropper is a tool that aims to automate the exploitation of ROP. Its goal is to become a tool that no longer requires user interaction.

# Installation
For now, you have to manually download pwn tools. This can be done by doing the following with Python3:
```
$ apt-get update
$ apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
$ python3 -m pip install --upgrade pip
$ python3 -m pip install --upgrade pwntools
```

# Usage
Since this is not the v1, you will have to do some stuff manually.<br>
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
<br>
Once at least two functions have been leaked, you can manually check on [blukat](https://libc.blukat.me/), download the right libc and then edit.
```py
LIBC = "./libc/libc6_2.31-0ubuntu9.2_amd64.so" # edit the PATH to your libc location.
```
Once it's done, restart the program and you should have a shell. Happy hacking! :-) 

# Contributing
Thanks to for helping me in this project:<br>
RedAmber<br>
Tim-ats-d
