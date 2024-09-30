
import struct
import textwrap

import sys

class Colors:
    RESET   = "\033[0m"
    BLACK   = "\033[30m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"

def wait():
    debug("press something to continue")    
    wait = input()

def okay(msg, *args):
    print(Colors.GREEN + "[+] " + msg.format(*args) + Colors.RESET, file=sys.stdout)

def warn(msg, *args):
    print(Colors.RED + "[-] " + msg.format(*args) + Colors.RESET, file=sys.stdout)

def info(msg, *args):
    print(Colors.YELLOW + "[i] " + msg.format(*args) + Colors.RESET, file=sys.stdout)

def spam(msg, *args):
    print(Colors.BLUE + "[i] " + msg.format(*args) + Colors.RESET, file=sys.stdout)

def debug(msg, *args):
    print(Colors.MAGENTA + "[#] debug " + msg.format(*args) + Colors.RESET, file=sys.stdout)
