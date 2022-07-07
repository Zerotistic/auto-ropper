# Auto-pwner
pwn is annoying so i made a tool for it<br>
i'm probably giving up on this project but pull requests are welcome

# install 
```
$ pip install -r requirements.txt
```

# Documentations
## Supports
* ROPchain (ret2win, ret2libc)
* Create boilerplate script in case of fail

## Auto-pwner V1
Auto-pwner is a tool that aims to automate the exploitation of ROPchain (for now). Its goal is to become a tool that no longer requires user interaction.

## Informations
I'm still working on this project, however i made it private. I may or may not make it public later. You can still create issue and pull request.

## Installation
You can simply do:
```
$ pip install -r requirements.txt
```

## Usage
Help page `python3 main.py -h`<br>
There's four options, three are used in CLI, last one is to start a GUI.
You can see each mode option by doing `python3 rop.py <mode> -h` <br>
Once you've started the program, you should wait around 5 seconds (depends on your internet) and you'll have a shell if the binary is pwnable. Happy hacking! :-) 

## Didn't pwn...
There can be various reasons as to why you didn't get a shell. 
1) The first one being, it didn't leaked the address correctly. You should try to run again the program 
2) Another reason can be it either didn't found a libc, or the libc doesn't seem pwnable (only when it's a modified libc)
3) The last reason is, you might just try to pwn something that is either not pwnable or that my tool can't pwn!

## To-do
* ~~Implement attack vector detection~~
- to implement
    * format string 
    * Command injection detection and exploitation
* ~~Upgrade ROPchain() attack for more binary~~
* Improve boilerplate script creation
* ~~reformat the code for better implementation in the future~~

## Bugs / Update
If you were to find a bug, please do create an issue.<br>
If you want to add something, you can fork and create a pull request, or you can create an issue. If it is an issue, i might take some time, or refuse to do it myself. 

