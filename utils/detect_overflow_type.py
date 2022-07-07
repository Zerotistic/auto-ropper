# pyright: reportMissingImports=false, reportUndefinedVariable=false
from pwn import *
import r2pipe
import json
import logging
log = logging.getLogger(__name__)

class Detect_overflow_type():
    def __init__(self, dict, binary):
        self.properties = dict
        self.binary = binary
        self.elf = ELF(self.binary)
        self.rop = ROP(self.elf)
        self.io = process(self.binary)
    
    def detect(self):
        # check if overflow is ret2win
        winfunc = self.get_win_functions()
        if winfunc:
            return "RET2WIN", winfunc
        else:
            return "RET2LIBC", None

    def get_win_functions(self):
        log.info("Searching for win function")
        winFunctions = {}
        r2 = r2pipe.open(self.binary)
        r2.cmd("aaa")
        all_funcs_json = r2.cmd("aflj")
        functions = [func for func in json.loads(all_funcs_json)]
        # Check for function that gives us system(/bin/sh)
        log.info("Checking for function that gives us system(/bin/sh) or execve(/bin/sh)")
        for func in functions:
            if "system" in str(func["name"]) or "execve" in str(func["name"]):
                system_name = func["name"]
                # Get XREFs
                refs = [
                    func for func in json.loads(r2.cmd(f"axtj @ {system_name}"))
                ]
                for ref in refs:
                    if "realname" in ref:
                        winFunctions[ref["realname"]] = ref

        # Check for function that reads flag.txt
        # Then prints flag.txt to STDOUT
        log.info("Checking for function that reads in a file that has a known file name")
        known_flag_names = ["flag", "pass", "pwd", "secret"]
        strings = [string for string in json.loads(r2.cmd("izj"))]
        for string in strings:
            value = string["string"]
            if any([x in value for x in known_flag_names]):
                address = string["vaddr"]
                # Get XREFs
                refs = [func for func in json.loads(r2.cmd(f"axtj @ {address}"))]
                for ref in refs:
                    if "realname" in ref:
                        winFunctions[ref["realname"]] = ref

        if winFunctions != {}:
            for k, v in list(winFunctions.items()):
                log.info(f"Found win function {k}")
        else:
            log.info("No win function found")
        return winFunctions