#!/usr/bin/env python

reg_table_21_0 = {
    'a': b'\x20',
    'b': b'\x04',
    'c': b'\x40',
    'd': b'\x02',
    's': b'\x08',
    'i': b'\x01',
    'f': b'\x10'
}
func_table_21_0 = {
    'imm': b'\x04',
    'add': b'\x00',
    'stk': b'\x01',
    'stm': b'\x40',
    'ldm': b'\x20',
    'cmp': b'\x02', 
    'jmp': b'\x08',
    'sys': b'\x10'
}

syscall_table_21_0 = {
    'open': b'\x10',
    'read': b'\x04',
    'write': b'\x01'
}

reg_table_21_1 = {
    'a': b'\x01',
    'b': b'\x40',
    'c': b'\x02',
    'd': b'\x08',
    's': b'\x20',
    'i': b'\x10',
    'f': b'\x04'
}
func_table_21_1 = {
    'imm': b'\x01',
    'add': b'\x04',
    'stk': b'\x08',
    'stm': b'\x10',
    'ldm': b'\x40',
    'cmp': b'\x00', 
    'jmp': b'\x20',
    'sys': b'\x02'
}
syscall_table_21_1 = {
    'open': b'\x20',
    'read': b'\x08',
    'write': b'\x01'
}

def str2hex_num(string = '/flag'):
    return [hex(ord(char)) for char in string]

# 'op arg1 arg2' ==> [arg1_byte|arg2_byte|op_byte]
def compile_instr(instr, reg_table, func_table, syscall_table, layout):
    arr = instr.split()
    if(len(arr) != 3):
        return b''
    op = arr[0]
    arg1 = arr[1]
    arg2 = arr[2]

    if(op == 'sys'):
        arg1 = syscall_table[arg1]
    elif(arg1 in 'abcdsif'):
        arg1 = reg_table[arg1]
    else:
        arg1 = bytes.fromhex(arg1[2:]) # drop '0x'

    if(arg2 in 'abcdsif'):
        arg2 = reg_table[arg2]
    else:
        arg2 = bytes.fromhex(arg2[2:]) # drop '0x'

    if(layout == '21o'):
        return arg2 + arg1 + func_table[op]
    else:
        return arg1 + func_table[op] + arg2

def compiler_loop(code, reg_table, func_table, syscall_table, layout = '21o'):
    instrs = code.split('\n')
    shellcode = b''
    for instr in instrs:
        shellcode = shellcode + compile_instr(instr, reg_table, func_table, syscall_table, layout)
    return shellcode

# "/flag\0" -> 0x2f, 0x66, 0x6c, 0x61, 0x67, 0x00
display_flag = '''
    imm a 0x00
    imm b 0x2f
    stm a b
    
    imm a 0x01
    imm b 0x66
    stm a b
    
    imm a 0x02
    imm b 0x6c
    stm a b
    
    imm a 0x03
    imm b 0x61
    stm a b
    
    imm a 0x04
    imm b 0x67
    stm a b
    
    imm a 0x05
    imm b 0x00
    stm a b

    imm a 0x00
    sys open a

    imm b 0x10
    imm c 0xef
    sys read a

    imm a 0x01
    imm b 0x10
    imm c 0xef
    sys write a
'''

def babyrev_lv21_0():
    shellcode = compiler_loop(display_flag, reg_table_21_0, func_table_21_0, syscall_table_21_0)
    with open('shellcode', 'wb') as f:
        f.write(shellcode)
        print(shellcode)

def babyrev_lv21_1():
    shellcode = compiler_loop(display_flag, reg_table_21_1, func_table_21_1, syscall_table_21_1, '1o2')
    with open('shellcode', 'wb') as f:
        f.write(shellcode)
        print(shellcode)
