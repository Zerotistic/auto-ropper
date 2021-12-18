# V2
It now has a parser so you don't have to edit the py file anymore. <br>
It's also able to attack remotly and localy.<br>
Dealt with some annoying issue in the binary test (added `setvbuf()`)<br>
In the future a session save will be added and i'll work on improving the pwning.


# V1
It is now able to do pretty much everything by itself:
* Leak offset
* Leak address
* Find and download libc
* Pwn
However you still need to edit the file to change the path and name for the binary you want to pwn. It'll be fixed in future version.<br>
It also cannot access online binary, but that'll be fixed too sooner than later.
