# Reverse Engineering
- *babyrev_level12.0*: this challenge is an custom emulator that emulates a completely custom architecture called "Yan85". This challenge is straightforward, debug the program and find the parameters of `memcmp()`, my input is `"123\n"`
    ```
    1: x/1i $rip
    => 0x55c4e42b101b <execute_program+208>:        call   0x55c4e42b0130 <memcmp@plt>
    2: x/8xb $rdi
    0x7ffd4730a64f: 0x70    0x28    0xd7    0x94    0xd6    0x02    0x97    0x71
    3: x/8xb $rsi
    0x7ffd4730a62f: 0x31    0x32    0x33    0x0a    0x00    0x00    0x00    0x00
    ```
    - So, the correct key should be `"\x70\x28\xd7\x94\xd6\x02\x97\x71"`
- *babyrev_level12.1*: still straightforward, this time we only need 4 bytes input
    ```
    (gdb) x/8bx $rsi
    0x7fff1034afba: 0x31    0x32    0x33    0x34    0x00    0x00    0x00    0x00
    (gdb) x/8bx $rdi
    0x7fff1034afda: 0xf6    0xc9    0x11    0xf5    0x00    0x00    0x00    0x00
    ```
- *babyrev_level13.0*: VM-based obfuscation. There are some VM code, but we don't need to reverse those code because we are clever, just go to the `memcmp()` and check its parameters. My input is `12345667`, the challenge compares my input directly with the key, without any process
    ```
    (gdb) x/8bx $rsi
    0x7ffecd1a3004: 0x31    0x32    0x33    0x34    0x35    0x36    0x36    0x37
    (gdb) x/8bx $rdi
    0x7ffecd1a3024: 0x10    0x56    0xf9    0x84    0x5e    0xd5    0xd8    0x10
    ```
- *babyrev_level13.1*: same as the 13.0, debug it and get the key
    ```
    (gdb) x/8bx $rdi
    0x7ffc819908a1: 0xb9    0xf8    0x6c    0x1b    0xe5    0x5a    0xa6    0x95
    ```
- *babyrev_level14.0*: same as 13.0
- *babyrev_level14.1*: same as 13.1
- *babyrev_level15.0*: same as 14.0
- *babyrev_level15.1*: same as 14.1
- *babyrev_level16.0*: from now on, we have to reverse the VM code even if we are clever. In this challenge, there is no `memcmp()`, but there are a few functions: `interpret_sys()`, `interpret_imm()`, `interpret_cmp()`, `interpret_add()`, `interpret_ldm()`, ...
    - Before each time a function with the prefix `interpret_` was called, the value passed to `rdi` is always `QWORD PTR [rbp-0x18]` (the `rbp` is the base pointer of the stack frame for `execute_program()`)
    - `interpret_sys`: 
        ```
        allocate 0x38 bytes on stack
        store rdi to a local variable QWORD PTR [rbp-0x38], denoted as q_38
        eax = edx (0x40)
        edx = rsi (0x10)
        store dl to BYTE PTR [rbp-0x3c], denoted as b_3c
        store al to BYTE PTR [rbp-0x40], denoted as b_40
        eax = b_40
        edi = eax
        call <describe_register>
        rdx = rax
        esi = b_3c
        rdi = address of format string "[s] SYS %#hhx %s\n"
        eax = 0
        call <printf@plt>
        eax = b_3c
        if(eax & 0x20) {
            // the key branch that will finally open "/flag"
            rdi = address of "[s] ... open"
            call <puts@plt>
            ...
        }
        else {
            eax = b_3c
            if(eax & 0x10) {
                rdi = address of "[s] ... read_memory"
                call <puts@plt>
                
                rdx = q_38
                
                rax = q_38
                eax = (BYTE PTR) (rax + 0x101)
                rax += rdx
                q_20 = rax
                
                rax = q_38
                eax = (BYTE PTR) (rax + 0x101)
                edx = 0x100 - eax
                eax = edx
                rdx = eax (movsxd)

                rax = q_38
                eax = (BYTE PTR) (rax + 0x102)
                if(rdx <= rax) {
                    rax = rdx
                }
                b_22 = al
                edx = b_22

                rax = q_38
                eax = (BYTE PTR) (rax + 0x100)
                rcx = q_20
                rsi = q_20
                edi = eax (0x00)
                call <read@plt> (read 4 bytes from stdin)

                ecx = b_40
                rax = q_38
                esi = b_40
                rdi = q_38
                call <write_register>

                eax = b_3c
                if(eax & 0x2) {
                    
                }
                else {
                    eax = b_3c
                    if(eax & 0x1) {

                    }
                    else {
                        eax = b_3c
                        if(eax & 0x8) {

                        }
                        else {
                            if(b_40 != 0) {
                                edx = b_40
                                rax = q_38
                                esi = b_40
                                rdi = q_38
                                call <read_register> // <interpret_sys+612>
                                ebx = al
                                edi = b_40
                                call <describe_register>
                                edx = ebx
                                rsi = rax
                                rdi = address of format string "[s] ... return value (in register %s): %#hhx\n"
                                eax = 0
                                call <printf@plt>
                                exit
                            }
                            else {
                                
                            }
                        }
                    }
                }
            }
            else {
                
            }
        }
        ```
    - `describe_register`:
        ```
        switch(dil) {
            case 0x40: rax = address of "a"; break;
            case 0x08: rax = address of "b"; break;
            case 0x02: rax = address of "c"; break;
            case 0x01: rax = address of "d"; break;
            case 0x10: rax = address of "s"; break;
            case 0x20: rax = address of "i"; break;
            case 0x04: rax = address of "f"; break;
            case 0x00: rax = address of "NONE"; break;
            default:   rax = address of "?";
        }
        ```
    - `write_register`:
        - Readable version
            ```
            OFFSET = TABLE[sil] ({0, 1, 2, 3, 4, 5, 6})
            BYTE PTR [rdi + 0x100 + OFFSET] = dl
            ```
        - Detailed process (for analysis)
            ```
            q_08 = rdi
            ecx = esi
            eax = edx
            edx = esi
            b_0c = sil
            b_10 = al

            rax = q_08
            edx = b_10
            swithc(sil) {
                case 0x40:
                    BYTE PTR [q_08+0x100]= b_10; break;
                case 0x08:
                    BYTE PTR [q_08+0x101]= b_10; break;
                case 0x02:
                    BYTE PTR [q_08+0x102]= b_10; break;
                case 0x01:
                    BYTE PTR [q_08+0x103]= b_10; break;
                case 0x10:
                    BYTE PTR [q_08+0x104]= b_10; break;
                case 0x20:
                    BYTE PTR [q_08+0x105]= b_10; break;
                case 0x04:
                    BYTE PTR [q_08+0x106]= b_10; break;
                default:
                    rdi = address of "unknown register"
                    crash
            }
            ```
    - `read_register`:
        - Readable version
            ```
            read_register(rdi, rsi) {
                OFFSET = TABLE[sil] ({0, 1, 2, 3, 4, 5, 6})
                eax = BYTE PTR [rdi + 0x100 + OFFSET]
            }
            ```
        - Detailed process
            ```
            q_08 = rdi
            eax = esi
            switch(al) {
                case 0x40: eax = BYTE PTR [q_08 + 0x100]; break;
                case 0x08: eax = BYTE PTR [q_08 + 0x101]; break;
                case 0x02: eax = BYTE PTR [q_08 + 0x102]; break;
                case 0x01: eax = BYTE PTR [q_08 + 0x103]; break;
                case 0x10: eax = BYTE PTR [q_08 + 0x104]; break;
                case 0x20: eax = BYTE PTR [q_08 + 0x105]; break;
                case 0x04: eax = BYTE PTR [q_08 + 0x106]; break;
                default:
                    rdi = address of "unknown register"
                    crash
            }
            ```
    - `interpret_imm`:
        - Use `sil` to select a 1-byte register, set its value to `dl`
        - Readable version
            ```
            interpret_imm(rdi, rsi, rdx) {
                describe_register(sil) // store register name address to eax
                printf("[s] IMM %s = %#hhx\n", eax, edx)
                write_register(rdi, sil, dl)
            }
            ```
        - Detailed process
            ```
            allocate 0x18 bytes on stack
            q_18 = rdi (0x7ffc74df2260)
            ecx = esi  (0x8)
            eax = edx  (0x91)
            edx = esi  (0x8)
            b_1c = dl
            b_20 = al
            ebx  = al
            eax  = dl
            edi  = dl
            call <describe_register>
            edx = ebx
            rsi = rax (address of "b")
            rdi = address of format string "[s] IMM %s = %#hhx\n"
            eax = 0
            call <printf@plt> ("IMM b = 0x91")
            edx = b_20 (0x91)
            ecx = b_1c (0x8)
            rax = q_18
            esi = b_1c (0x8)
            rdi = q_18
            call <write_register> (write b_20 to register "b")
            exit
            ```
    - `interpret_stm`:
        - Readable version
            ```
            interpret_stm(rdi, rsi, rdx) {
                reg1 = describe_register(rdx)
                reg2 = describe_register(rsi)
                printf("[s] STM *%s = %s\n", reg2, reg1)
                reg1_val = read_register(rdi, dl)
                reg2_val = read_register(rdi, sil)
                write_memory(rdi, reg2_val, reg1_val)
            }
            ```
        - Detailed process
            ```
            (rdi: base address for registers)
            (rsi: 0x8)
            (rdx: 0x40)
            allocate 0x18 bytes on stack
            q_18 = rdi
            ecx = esi (0x8)
            b_1c = sil (0x8)
            b_20 = dl  (0x40)
            edi  = b_20
            call <describe_register> (get "a")
            rbx  = rax // address of register "a"
            edi  = b_1c
            call <describe_register> (get "b")
            rdx  = rbx // address of register "a"
            rsi  = rax // address of register "b"
            rdi  = address of format string "[s] STM *%s = %s\n"
            eax  = 0
            call <printf@plt>
            
            rdi = q_18
            esi = b_20
            call <read_register>
            ebx = al

            rdi = q_18
            esi = b_1c
            call <read_register>
            ecx = al

            edx = ebx // value in "a"
            rsi = ecx // value in "b"
            rdi = q_18
            call <write_memory>

            exit
            ```
    - `write_memory`:
        - Readable version
            ```
            write_memory(rdi, rsi, rdx) {
                BYTE PTR [rdi + rsi] = dl
            }
            ```
    - `interpret_add`:
        - Readable version
            ```
            // reg(rsi) = reg(rsi) + reg(rdx)
            interpret_add(rdi, rsi, rdx) {
                reg1 = describe_register(sil)
                reg2 = describe_register(dl)
                printf("[s] ADD %s %s\n", reg1, reg2)
                reg1_val = read_register(rdi, sil)
                reg2_val = read_register(rdi, dl)
                write_register(rdi, sil, reg1_val + reg2_val)
            }
            ```
        - Detailed process
            ```
            (rdi: base address for registers)
            (rsi: 0x8)
            (rdx: 0x2)
            allocate 0x18 bytes on stack
            q_18 = rdi

            b_1c = esi  (0x8)
            b_20 = dl   (0x2)
            edi  = b_20 (0x2)
            call <describe_register>
            rbx = rax // register "c"
            edi  = b_1c  (0x8)
            call <describe_register>
            rdx  = rbx // register "c"
            rsi  = rax // register "b"
            rdi  = &"[s] ADD %s %s\n"
            eax  = 0
            call <printf@plt> // [s] ADD b c

            rsi = b_1c
            rdi = q_18
            call <read_register>
            ebx = eax // value of "b"
            rsi = b_20
            rdi = q_18
            call <read_register>
            eax += ebx // eax = val_b + val_c

            edx = al
            esi = b_1c
            rdi = q_18
            call <write_register>
            
            exit
            ```
    - `interpret_ldm`:
        - Readable version
            ```
            interpret_ldm(rdi, rsi, rdx) {
                // b_1c rsi
                // b_20 rdx
                reg1 = describe_register(dl)
                reg2 = describe_register(sil)
                printf([s] LDM %s = *%s\n, reg2, reg1)
                
                reg1_val = read_register(rdi, dl)
                mem_val = read_memory(rdi, reg1_val)

                write_register(rdi, rsi, mem_val)

                exit
            }
            ```
    - `read_memory`:
        - Readable version
            ```
            read_memory(rdi, rsi) {
                eax = BYTE PTR [rdi + rsi]
            }
            ```
    - `interpret_cmp`:
        - Readable version
            ```
            (rsi 0x40)
            (rdx 0x8)
            interpret_cmp(rdi, rsi, rdx) {
                reg1 = describe_register(dl)
                reg2 = describe_register(sil)
                printf("[s] CMP %s %s\n", reg2, reg1)

                reg1_val = read_register(rdi, dl)
                reg2_val = read_register(rdi, sil)

                if(reg2_val < reg1_val) {
                    reg_6 = 0x9
                }
                if(reg2_val > reg1_val) {
                    reg_6 = 0x11
                }
                if(reg2_val == reg1_val) {
                    reg_6 = (reg2_val != 0) ? 0x4 : 0x6
                }
            }
            ```
        - Detailed process
            ```
            allocate 0x28 bytes on stack
            q_28 = rdi
            b_2c = sil
            b_30 = dl
            edi  = b_30
            call <describe_register>
            rbx = rax
            edi = b_2c
            call <describe_register>
            rdx = rbx
            rsi = rax
            rdi = &"[s] CMP %s %s\n"
            call <printf@plt> // [s] CMP a b

            esi = b_2c
            rdi = q_28
            call <read_register>
            b_12 = al

            esi = b_30
            rdi = q_28
            call <read_register>
            b_11 = al

            BYTE PTR [q_28 + 0x106] = 0 (the last register, reg_6)
            cmp b_12, b_11
            jae <+165>
            reg_6 = reg_6 or 0x8
            <+165> cmp b_12, b_11
            jbe <+200>
            reg_6 = reg_6 or 0x10
            <+200> cmp b_12, b_11
            jne <+235>
            reg_6 = reg_6 or 0x4
            <+235> cmp b_12, b_11
            je <+270>
            reg_6 = reg_6 or 0x1
            <+270> cmp b_12, 0x0
            jne <+308>
            cmp b_11, 0x0
            jne <+308>
            reg_6 = reg_6 or 0x2
            <+308> exit
            ```
        - `execute_program`
            - Start from the comparison
                ```
                (q_18 stores the base address)
                d_4 = 1
                (1)
                reg_1 = [q_18 + 0x91]
                reg_0 = [q_18 + 0x71] // first byte of our input
                if(reg_1 != reg_0) {
                    d_4 = 0
                }
                (2)
                reg_1 = [q_18 + 0x92]
                reg_0 = [q_18 + 0x72]
                if(reg_1 != reg_0) {
                    d_4 = 0
                }
                (3)
                reg_1 = [q_18 + 0x93]
                reg_0 = [q_18 + 0x73]
                if(reg_1 != reg_0) {
                    d_4 = 0
                }
                (4)
                reg_1 = [q_18 + 0x94]
                reg_0 = [q_18 + 0x74]
                if(reg_1 != reg_0) {
                    d_4 = 0
                }
                ```
    - Now, we can see that the 4 bytes key stored in `[q_18 + 0x91]`, we can try to input "\x9d\xa4\x8c\xd2". Got the flag.
        ```
        (gdb) x/8bx 0x7ffcccc08c51
        0x7ffcccc08c51: 0x9d    0xa4    0x8c    0xd2    0x00    0x00    0x00    0x00
        ```
- *babyrev_level16.1*: similar to 16.0, but gets some useful information removed. 
    - Based on previous analysis, the key is 8 bytes, and starts from offset `0x96`
- *babyrev_level17.0*: debug it, get to the place right before the `cmp`s, and see the key
- *babyrev_level17.1*: debug it, get to the place right before the `cmp`s, and see the key
- *babyrev_level18.0*: a little bit more complex
    ```
    input = key+offset
    symbolic value: [0x64]+0x86 [0x65]+0xf9 [0x66]+0x5e [0x67]+0xb [0x68]+0xbc [0x69]+0x84
    concrete value:  c2          55          1e          b8         a4          d1
    ```
- *babyrev_level18.1*
    ```
    input = key-offset
    0x7f-0x4d  0x79-0xd8 0xc0-0x13 0x49-0x77 0x2e-0xf4 0x5a-0x46 0x24-0x4b 0xc2-0x86 0xb0-0x33
    0x32       0xa1      0xad      0xd2      0x3a      0x14      0xd9      0x3c      0x7d
    ```
- *babyrev_level19.0*: this is a full end-to-end obfuscated challenge, like we might see in real-world obfuscated code! The key functions are `interpreter_loop` and `interpret_instruction`
    - `main`
        1. `memcopy` the VM code at `vm_code` on to the stack (from `rbp-0x410`)
        2. move content in `vm_mem` on to the stack
            ```
            vm_mem offset: +0     +8     +16    +24   ... +240  +248
            rbp    offset: -0x110 -0x108 -0x100 -0xf8 ... -0x20 -0x18
            ```
        3. call `interpreter_loop` with parameter `rdi = rbp-0x410` (the start of VM code on stack). In `interpreter_loop`, the VM code bytes will be interpreted by `interpret_instruction` function
    - `interpreter_loop`
        ```
        allocate 0x20 bytes on stack
        q_18 = rdi (address of the VM code on stack)
        
        loop_start:
        eax  = BYTE PTR [q_18+0x405] ([rbp_main-0xb])
        BYTE PTR [q_18+0x405] += 1

        // we can figure out that each instruction is 3 bytes
        // suppose the instruction is [A|B|C] (low to high address)
        rax  = 3 * rax + q_18
        edx  = WORD PTR [rax]     // [A|B]
        eax  = BYTE PTR [rax+0x2] // [C]
        // the 3 bytes from `rbp-0x3` is used to store the instruction
        w_03  = dx  // [A|B]
        b_01  = al  // [C]

        edx  = b_03 //  [A]
        ecx  = b_02 //  [B]
        rcx <<= 8   //  [00|B]
        rcx |= rdx  //  [A|B]
        edx  = b_01 //  [C]
        rdx <<= 16  //  [00|00|C]
        rdx |= rcx  //  [A|B|C]
        rsi  = rdx  //  [A|B|C]
        rdi  = q_18
        call <interpret_instruction>
        jmp loop_start
        ```
    - `interpret_instruction`
        ```
        allocate 0x10 bytes on stack
        q_08 = rdi // starting address of VM code on stack
        q_10 = rsi // 3-byte instruction to be interpreted
        edi  = BYTE PTR [q_08 + 0x406]
        esi  = BYTE PTR [q_08 + 0x405]
        r9d  = BYTE PTR [q_08 + 0x404]
        r8d  = BYTE PTR [q_08 + 0x403]
        ecx  = BYTE PTR [q_08 + 0x402]
        edx  = BYTE PTR [q_08 + 0x401]
        eax  = BYTE PTR [q_08 + 0x400]
        push rdi
        push rsi
        esi = eax
        rdi = &"[V] a:%#hhx b:%#hhx c:%#hhx d:%#hhx s:%#hhx i:%#hhx f:%#hhx\n"
        print out the values in registers: a, b, c, d, s, i, f

        rsp += 0x10
        // get the instruction [al | cl | dl] (low -> high)
        ecx = b_0f
        edx = b_0e
        eax = b_10
        esi = eax
        rdi = &"[I] op:%#hhx arg1:%#hhx arg2:%#hhx\n"
        print out the instruction "op:al arg1:dl arg2:cl"

        switch(al) {
            case 0x2:  interpret_imm; break;
            case 0x40: interpret_add; break;
            case 0x10: interpret_stk; break;
            case 0x8:  interpret_stm; break;
            case 0x1:  interpret_ldm; break;
            case 0x4:  interpret_cmp; break;
            case 0x20: interpret_jmp; break;
            case 0x0:  interpret_sys; break;
            default:   NOP
        }
        ```
    - Register table
        ```
        0x4   a  0x400
        0x10  b  0x401
        0x1   c  0x402
        0x8   d  0x403
        0x2   s  0x404
        0x20  i  0x405
        0x40  f  0x406
        ```
    - `interpret_cmp`
        ```
        q_28 = rdi
        q_30 = rsi // [op_cmp|arg2|arg1]
        reg2 = describe_register(arg2)
        reg1 = describe_register(arg1)
        printf("[s] CMP %s %s\n", reg1, reg2)
 
        b_12 = read_register(q_28, arg1)
        b_11 = read_register(q_28, arg2)
        
        compare b_11 and b_12, and set reg_f
        ```
    - `interpret_stk`
        ```
        allocate 0x18 bytes on stack
        q_18 = rdi
        q_20 = rsi // [op_cmp|arg2|arg1]
        reg2 = describe_register(arg2)
        reg1 = describe_register(arg1)
        print out op_stk, arg1, arg2
        // push reg[arg2] on to the stack
        if(arg2 != 0) {
            printf("[s] ... pushing %s\n", reg2)
            reg_s += 1 // the s register is like a rsp in x86_64
            reg2_val = read_register(q_18, arg2)
            write_memory(q_18, reg_s, reg2_val)
        }
        // pop a value to reg[arg1]
        else if(arg1 != 0) {
            printf("[s] ... popping %s\n", reg1)
            top_val = read_memory(rdi, reg_s)
            write_register(rdi, arg1, top_val)
            reg_s -= 1
        }
        ```
    - `interpret_jmp`
        ```
        allocate 0x18 bytes on stack
        q_18 = rdi
        q_20 = rsi // [op_cmp|arg2|arg1]

        if(arg1 != 0 && (reg_f & arg1) == 0) {
            puts("[j] ... NOT TAKEN")
        }
        else {
            puts("[j] ... TAKEN")
            reg2_val = read_register(q_18, arg2)
            // overwrite register i (just like the rip in x86_64)
            reg_i = reg2_val
        }

        ```
    - Instructions in each loop
        ```
        i = 0xb8

        // for convenience
        write_memory(rdi, 0x77, 0xeb)
        write_memory(rdi, 0x78, 0xd9)
        write_memory(rdi, 0x79, 0xce)
        write_memory(rdi, 0x7a, 0xdd)
        write_memory(rdi, 0x7b, 0x46)
        write_memory(rdi, 0x7c, 0x10)
        write_memory(rdi, 0x7d, 0x9e)
        write_memory(rdi, 0x7e, 0x44)

        i = 0x98
        push a (0x00)
        push b (0x00)
        push c (0x7e)

        b = 0x1
        b = b + s (0x1+0x3)

        push 0x4b
        push 0x45
        push 0x59
        push 0x3a
        push 0x20

        c = 0x5
        a = 0x1
        SYS 0x20 d { // 0x20 is the number for write
            q_18 = vm_base+0x300+b

            edx = 0x100 - b
            eax = 0x100 - b
            rdx = 0x100 - b
            
            eax = min(c, 0x100-b)
            edx  = al
            rsi = vm_base+0x300+b
            edi = a
            call <write@plt>
            write return value of <write@plt> to register d (specified by arg1 0x8)
        }

        pop c (0x20)
        pop b (0x3a)
        pop a (0x59)
        push a (0x59)
        push b (0x3a)
        push c (0x20)
        
        b = 0x30
        c = 0x8
        a = 0x0

        SYS 0x4 d { // 0x4 is the number for read
            q_20 = vm_base+0x300+b

            // this is to prevent the input overwrite the data
            // after vm_base+0x400 (registers)
            edx = min(0x100 - b, c)
            rsi = q_20
            rdi = a
            call <read@plt>
            write the return value of <read@plt> to register d
        }
        
        pop c (0x20)
        pop b (0x3a)
        pop a (0x59)
        i = 0x5e
        push a (0x59)
        push b (0x3a)
        push c (0x20)

        pop c (0x20)
        pop b (0x3a)
        pop a (0x59)
        i = 0x1
        push a (0x59)
        push b (0x3a)
        push c (0x20)      

        a = 0x30
        b = 0x79
        c = 0x06
        d = 0x2
        d = d + i (0x2 + 0x6)
        push d (0x8)
        i = 0x82
        a = a + c (0x30 + 0x6)
        b = b + c (0x79 + 0x6)
        d = 0xff
        a = a + d (0x36 + 0xff)
        b = b + d (0x7f + 0xff)

        push a (0x35)
        push b (0x7e)

        a = [a] ([0x35] = 0x36)
        b = [b] ([0x7e] = 0x44)

        CMP a b
        ```
        - `a != b`: we can see that one thing different from the previous challenge is that when the current byte check fails, it will not check the rest of the bytes, but get "INCORRECT" immediately
            ```
            CMP a b (reg_f = 0x18)

            pop b (0x7e)
            pop a (0x35)

            d = 0x96
            JMP N d (taken, i = 0x97)

            push c (0x6)
            pop  d (0x6)
            pop  i (0x09)

            c = 0x0
            CMP d c (reg_f = 0x12)
            
            d = 0xe
            JMP E d (not taken)
            d = 0x65
            JMP LG d (taken, i = 0x66)

            b = 0x1
            b = b + s (0x1 + 0x5)

            push 0x49
            push 0x4e
            push 0x43
            push 0x4f
            push 0x52
            push 0x52
            push 0x45
            push 0x43
            push 0x54
            push 0x21
            push 0xa

            c = 0xb
            a = 0x1
            
            SYS 0x20 d (write "INCORRECT!")
            ```
        - `a == b` (in `gdb`, set the byte to be compared to the correct value)
            ```
            CMP a b (reg_f = 0x1)
            pop b (0x7e)
            pop a (0x35)
            d = 0x96
            jmp N d (not taken)
            d = 0xff
            c = c + d (0x06 + 0xff = 0x05)
            d = 0
            cmp c d (reg_f = 0x12)
            d = 0x84
            jmp N d (taken, i = 0x85)
            d = 0xff
            a = a + d (0x35 + 0xff = 0x34)
            b = b + d (0x7e + 0xff = 0x7d)

            push a
            push b
            a = [a] ([0x34] = 0x35, modify it to 0x9e)
            b = [b] ([0x7d] = 0x9e)

            we don't need to analyze the rest of instructions
            just keep running, and figure out the memory address being compared each time
            then we can figure out the key
            ```
        - addresses being compared: finally we can see that only the first 6 bytes of out input will be used
            ```
            1: [0x35] [0x7e], 0x44
            2: [0x34] [0x7d], 0x9e
            3: [0x33] [0x7c], 0x10
            4: [0x32] [0x7b], 0x46
            5: [0x31] [0x7a], 0xdd
            6: [0x30] [0x79], 0xce
            DONE
            ```
- *babyrev_level19.1*: the VM instruction information will not be given, we need to inspect the code to figure out some key functions' address
    - input: `base + 0x330`
    - key: `base + 0x376`
    - this time, the challenge program takes 8 bytes as input, and compares the first 6 bytes of our input with the 6-byte key
- *babyrev_level20.0*:
    - this time our input will be processed
        ```
        [0x30] += 0xed
        [0x31] += 0x7b
        [0x32] += 0x56
        [0x33] += 0x2a
        [0x34] += 0x5e
        [0x35] += 0xeb
        [0x36] += 0x72
        [0x37] += 0x79
        [0x38] += 0x6c
        [0x39] += 0x1a
        [0x3a] += 0x76
        [0x3b] += 0xc9
        [0x3c] += 0x94
        [0x3d] += 0x6
        [0x3e] += 0xd3
        [0x3f] += 0x29
        [0x40] += 0xd3
        [0x41] += 0xb5
        [0x42] += 0x7b
        [0x43] += 0x31
        [0x44] += 0x4f
        ```
    - the challenge will compare the processed 21 bytes with the key
- *babyrev_level20.1*: same. An easy way is to observe the registers to figure out what happend to our input
- *babyrev_level21.0*: we need to write the shellcode that can be interpreted by this custom emulator. We can call `interpret_sys` in our shellcode, and get it to execute the `open` branch
    - Mind that this time the layout of the instruction is a little bit different:
        - Instructions are still 3 bytes
        - But from low to high memory, they are `[arg2|0x10|op]`
    - `open` in `interpret_sys`: opens a file and store the FD in a register specified by `rsi`
        ```
        q_38 = rdi
        q_40 = rsi
        ...
        // to reach this branch, arg1 should be 0x10: [arg2|0x10|op_sys] (low -> high)
        puts("[s] ... open")
        edx = reg_c
        eax = reg_b
        esi = reg_b
        rdi = q_38 + 0x300 + reg_a
        call <open@plt>
        write_register(q_38, arg1, al)
        ```
        - We can use `sys 0x10 a` to open a file and store the FD in register `a`
        - One thing we need to do is to make `rdi` the address of the flag path `"/flag"`
            ```
            // "/flag\0" -> 0x2f, 0x66, 0x6c, 0x61, 0x67, 0x00
            imm a 0x00
            imm b 0x2f
            stm a b
            imm a 0x01
            imm b 0x66
            stm a b
            ...
            ```
        - Then, we can set `a` to `0x00` (the `open` system call get file path from `base + 0x300 + a`), and call `open`. The result will be stored in `a` as we specified
            ```
            imm a 0x00
            sys 0x10 a
            ```
    - `read` in `interpret_sys`: `read(a, base + 0x300 + b, min(0x100 - b, c))`
        ```
        q_38 = rdi
        q_40 = rsi
        ...
        // to reach this branch, arg1 should be 0x04: [arg2|0x04|op_sys] (low -> high)
        rdx = min(0x100 - reg_b, reg_c)
        rsi = q_38 + 0x300 + reg_b
        rdi = reg_a
        call <read@plt>
        ```
        - We need to set `a` to the FD of the flag file (it is already set by the previous system call), `b` to the offset of the address where we want to store the flag (`0x10`), `c` to `0xef`
            ```
            imm b 0x10
            imm c 0xef
            sys 0x04 a
            ```
    - `write` in `interpret_sys`: `write(a, base + 0x300 + b, min(0x100 - b, c))`
        ```
        q_38 = rdi
        q_40 = rsi
        ...
        // to reach this branch, arg1 should be 0x01: [arg2|0x01|op_sys] (low -> high)
        rdx = min(0x100 - reg_b, reg_c)
        rsi = q_38 + 0x300 + reg_b
        rdi = reg_a
        call <write@plt>
        ```
        - We need to set `a` to the FD of standard output (`0x01`), `b` to the offset of the begnning of the flag (`0x10`), `c` to `0xef`
            ```
            imm a 0x01
            imm b 0x10
            imm c 0xef
            sys 0x01 a
            ```
- *babyrev_level21.1*: Bad news is that the byte for registers, functions, and system calls are changed, and the layout of the instruction becomes `[arg1|op|arg2] (L -> H)`. Good news is that we do not need to modify the custom code, we just need to modify the convert table and `compile_instr`
    - Register table
        ```
        reg_table_21_1 = {
            'a': b'\x01',
            'b': b'\x04',
            'c': b'\x40',
            'd': b'\x02',
            's': b'\x08',
            'i': b'\x01',
            'f': b'\x10'
        }
        ```
    - Function table
        ```
        func_table_21_1 = {
            'imm': b'\x04',
            'add': b'\x00',
            'stk': b'\x01',
            'stm': b'\x40',
            'ldm': b'\x20',
            'cmp': b'\x02', 
            'jmp': b'\x08',
            'sys': b'\x10'
        }
        ```
    - System call table
        ```
        open:  0x20
        read:  0x08
        write: 0x01
        ```
    - There are 2 `read` sysyem calls
        - `0x10`
            ```
            q_28 = rdi
            q_30 = rsi
            ...
            rcx = min((0x100 - reg_b) * 3, reg_c)
            rsi = q_28 + reg_b * 3
            rdi = reg_a
            call <read@plt>
            ```
        - `0x08`, we will use this one for this challenge
            ```
            q_28 = rdi
            q_30 = rsi
            ...
            rdx = min(0x100 - reg_b, reg_c)
            rsi = q_28 + 0x300 + reg_b
            rdi = reg_a
            call <read@plt>
            ```
- *babyrev_level22.0*: this challenge randomized the VM based on the value of the flag. This means that there is no way for us to know the opcode and argument encodings. Find a side channel!
    - First, analyze some functions
        - `flag_seed`: opens the `/flag` file and generate the seed, divide the flag into 4-byte group, XOR all groups, use the result as a seed for `srand()`
            ```
            // open "/flag", and read its content on to the stack
            read(open("/flag", 0), rbp-0x90, 0x80)

            d_9c = 0x0
            d_98 = 0x0

            while(d_98 <= 0x1f) {
                // each loop fetch 4 bytes of the flag
                // (rbp - 0x90) is the address of the flag
                eax = DWORD PTR [rbp - 0x90 + d_98 * 4]
                d_9c = d_9c xor eax
                
                d_98 += 1
            }

            srand(d_9c)

            // clear the flag content from memory
            memset(rbp - 0x90, 0x0, 0x80)
            ```
        - `shuffle_values`: there are `0xffff` loops, in each loop, it randomly swaps 2 values in `VALUE[i]`, where `i` is in `[-7, 7]`
            ```
            allocate 0x10 bytes on stack
            d_0c = 0
            while(d_0c <= 0xfffe) {
                call <rand@plt>
                cdq // sign-extend the value in 'eax' into 'edx:eax'
                shr edx, 0x1d // edx will be either 0x7 or 0x0
                eax += edx
                eax &= 0x7
                eax -= edx
                // the above steps turns eax into a signed value in [-7, 7]
                // specifically, edx = 0 when eax >= 0, edx = 0x7 when eax <=0
                // 'eax &= 0x7' makes eax a value from 0 to 7
                // so, eax -= edx makes eax a value in [-7, 7]
                d_08 = eax

                call <rand@plt>
                cdq // sign-extend the value in 'eax' into 'edx:eax'
                shr edx, 0x1d
                eax += edx
                eax &= 0x7
                eax -= edx
                d_04 = eax

                swap BYTE in VALUES[d_08] and VALUES[d_04] {
                    // details
                    eax = d_08
                    cdqe // sign-extend the value in 'eax' into 'rax'
                    b_0d = BYTE PTR [&VALUES + rax]
                    
                    eax = d_04
                    cdqe
                    edx = BYTE PTR [&VALUES + rax]
                    
                    eax = d_08
                    cdqe
                    BYTE PTR [$VALUES + rax] = dl
                    
                    eax = d_04
                    cdqe
                    BYTE PTR [$VALUES + rax] = b_0d
                }

                d_0c += 1
            }
            ```
        - `rerandomize`: assign the encoding byte value to the registers and functions, randomly
            ```
            call <shuffle_values>
            SPEC_REG_A = VALUES
            SPEC_REG_B = VALUES + 1
            SPEC_REG_C = VALUES + 2
            SPEC_REG_D = VALUES + 3
            SPEC_REG_S = VALUES + 4
            SPEC_REG_I = VALUES + 5
            SPEC_REG_F = VALUES + 6

            call <shuffle_values>
            INST_IMM = VALUES
            INST_STK = VALUES + 1
            INST_ADD = VALUES + 2
            INST_STM = VALUES + 3
            INST_LDM = VALUES + 4
            INST_JMP = VALUES + 5
            INST_CMP = VALUES + 6
            INST_SYS = VALUES + 7
            ```
    - One side channel is the output of the program, we can use it to probe the encoding and the functions or registers.
        - For example, we can learn from the following result that `SYS: 0x02`, `open: 0x02`, `reg_i: 0x04`, and the instruction format is `[arg1|op|arg2]`
            ```
            printf "\x02\x02\x04" | /challenge/babyrev_level22.0
            [I] op:0x2 arg1:0x2 arg2:0x4
            [s] SYS 0x2 i
            [s] ... open
            printf "\x01\x02\x04" | /challenge/babyrev_level22.0
            [I] op:0x2 arg1:0x1 arg2:0x4
            [s] SYS 0x1 i
            [s] ... return value (in register i): 0x1
            ```
        - Keep trying, and we can get the register, function, and syscall tables
            - Register table
                ```
                reg_table_22_0 = {
                    'a': b'\x10',
                    'b': b'\x08',
                    'c': b'\x80',
                    'd': b'\x01',
                    's': b'\x40',
                    'i': b'\x04',
                    'f': b'\x20'
                }
                ```
            - Function table
                ```
                func_table_22_0 = {
                    'imm': b'\x10',
                    'stm': b'\x08',
                    'sys': b'\x02'
                }
                ```
            - System call table
                ```
                syscall_table_22_0 = {
                    'open':  b'\x02',
                    'read':  b'\x40',
                    'write': b'\x10'
                }
                ```
- *babyrev_level22.1*: this time we cannot know what instruction our input is, the only information we can get is the error information, e.g., `unknown register`
    1. Figure out the instruction format
        - We first use "\x02\x02\x02" as input, no error is displayed, that means this is a valid instruction
        - Modify the first or third byte (separately) to "\x09", in both cases, there is an `unknown register` value. So, we can conclude that the instruction format should be `[arg|op|arg] (L->H)`, and the function `0x2` takes 2 registers as input
    2. Fiure out the parameter type of each function
        - From previous challenges we know that
            ```
            function    arg1        arg2
            imm         register    value
            add         register    register
            stk         reg or 0    reg or 0
            stm         register    register
            ldm         register    register
            cmp         register    register
            jmp         value       register
            sys         value       register // the value must be one of the specified values
            ```
        - Try different inputs. Since `[0x0|0x1|0x1]` is valid, but `[0x0|0x1|0x2]` gets an `unknown register` error, we can infer that the instruction format is `[arg2|op|arg1]`, and `SYS`'s encoding is `0x1`, and syscall `exit` is `0x1`
            ```
            function    arg1    arg2
            0x00        val     val

            0x01 sys    0x1     val
                        other   reg
            0x02        reg     reg
            0x04        reg     reg
            0x08        reg     reg
            0x10        reg     reg
            0x20 imm    reg     val
            0x40        val     reg

            0x80 stk    0/reg   0/reg
            ```
        - We can figure out the encoding for `sys` and `imm`, but for other information we need, including: `open`, `read (memory)`, `write`, and `stm`, we cannot infer them directly
            ```
            func or syscall     encoding
            open                {0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80}
            read (mem)          {0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80}
            write               {0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80}
            stm                 {0x2, 0x4, 0x8, 0x10}
            ```
    - To figure out register `i`'s encoding, we can input `ldm ? 0xff; sys exit 0`, if `?` is `i`, the code will jump over the exit `exit`, and the program will not end. We can find that `"\xff\x20\x04\x00\x01\x01"` will make the program keep running. So, `i` is `0x4`
    - For registers, notice that there is a `sleep` syscall, and it takes register `a` as input, we can try to set all registers except `i` to `0xff`, and then try all syscalls, there will be one syscall that blocks the program for a while. To see the effect, we put this syscall right before an exit syscall: `"\xff\x20\x01\xff\x20\x02\xff\x20\x08\xff\x20\x20\xff\x20\x40\xff\x20\x80\x01\x01\x??\x01\x01\x01"`. The result is that `sleep` is `0x40`, and we can modify one register at a time from `0xff` to `0x00`, when we set register `0x80` to `0x00`, the `sleep` will no longer block the program, so `0x80` is register `a`
    - Now we can try to find `read` syscall. Set `a` to FD of stdin or stdout (because in previous challenge, I found a strange thing, that is, I could only input from terminal when `a` is stdout, although I was expecting that `a` should be stdin). Then we set all other registers except `i` to `0x50`, that will ensure `b` and `c` are `0x50`. If we get `read` executed, the program should pause. Input: `"\x50\x20\x01\x50\x20\x02\x50\x20\x08\x50\x20\x20\x50\x20\x40\x01\x20\x80\x01\x01\x??\x01\x01\x01"`. The result is that `read` is `0x08` or `0x80` (one of them is read memmory, another is read instruction), to figure out which is read memory, we need to use `write` to test them
    - For syscall `write`, we can first use `read` to input something, and then try all other syscalls, if we get `write`, our input will be printed out. Input: `"\x50\x20\x01\x50\x20\x02\x50\x20\x08\x50\x20\x20\x50\x20\x40\x01\x20\x80\x01\x01\x??\x50\x20\x01\x50\x20\x02\x50\x20\x08\x50\x20\x20\x50\x20\x40\x01\x20\x80\x01\x01\x??\x01\x01\x01"`, the first `??` is `08` or `80`
        - Finally, we can found that `0x80` is `read_memory`, `0x02` is `write`
    - To figure out register `b`, we can use the input in the previous section, but each time, modify one register to `0x10`, if `b` is modified, there will not be any output. `b` is `0x2`
    - Similarly, we can figure out `c`: `c` is `0x20`
    - For `stm`, we can figure it out with the help of `write`. First, set `a` to `0x00`, `b` to `0x31`, then if we can `stm a b`, and call `write(0x1, 0x00, 0x10)`, `1` will be displayed. Input: `"\x00\x20\x80\x32\x20\x02\x??\x04\x80\x01\x20\x80\x00\x20\x02\x10\x20\x20\x01\x01\x02"`
        - `stm` is `0x2`
    - Now, here is what we have
        - Registers:
            ```
            a: 0x80
            b: 0x02
            c: 0x20
            ```
        - Functions:
            ```
            0x01 sys
            0x02 stm
            0x20 imm
            ```
        - Syscalls:
            ```
            0x02 write
            0x80 read (mem)
            ```
    
