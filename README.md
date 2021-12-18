# Auto-Ropper V2
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
This name the core file generated from the crash as `core`, which is the name of the file that Auto-Ropper will be looking for.<br><br>
Help page `python3 rop.py -h`<br>
There's three option, two are used for CLI, last one is to start a GUI (not available at the moment, will be later.)
You can see each mode option by doing `python3 rop.py <mode> -h`

```
usage: rop.py [-h] {local,remote,gui} ...

Auto-ropper is a tool that aims to automate the exploitation of ROP.

optional arguments:
  -h, --help          show this help message and exit

mode:
  {local,remote,gui}
```

Once you've started the program, you should wait around 15 seconds (depends on your internet) and you'll have a shell. Happy hacking! :-) 
# Preview
Here is what it should looks like when using Auto-Ropper V2<br>
[![asciicast](https://asciinema.org/a/X8Hqy0rXJr613rNfHjfmrJnS8.svg)](https://asciinema.org/a/X8Hqy0rXJr613rNfHjfmrJnS8)

# When and what will be V3?
V3 will include a session save as well as a GUI. While it *should* also currently works on Windows, V3 will make sure it does!<br>
I'm planning something big for the V3, but you can still refer to the `Bugs / Update` section if you want something specific!

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
@Red-Amber <br>
@Tim-ats-d
