# Auto-Ropper V0.3
Auto-ropper is a tool that aims to automate the exploitation of ROPchain. Its goal is to become a tool that no longer requires user interaction.

# Installation
You can simply do:
```
$ pip install -r requirements.txt
```

# Usage
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
Here is what it should looks like when using Auto-Ropper V1<br>
[![asciicast](https://asciinema.org/a/kH3wpPWPTWwjz24wHa5d9DDUR.svg)](https://asciinema.org/a/kH3wpPWPTWwjz24wHa5d9DDUR)

# When and what will be V1?
I don't know when it'll be. But it'll be for sure before june.<br>
V1 will include a session save as well as a GUI.<br>
I'm planning something big for the V1, but you can still refer to the `Bugs / Update` section if you want something specific!

# Didn't pwn...
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
