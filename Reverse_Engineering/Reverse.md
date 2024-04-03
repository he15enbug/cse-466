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
    - `vm_code` starts from `0x56086b87b020`
    - `vm_mem` starts from `0x56086b87b2e0`
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
    - We jump to the first `interpret_cmp`, finish it, and then we will see what happend to our input before the comparison
        - After the first `cmp` (modify the values being compared to the same)
            1. `imm d = 0xe`
            2. `jmp E d` (Not taken)
            3. `imm d = 0x65`
            4. `jmp LG d` (TAKEN)
            5. `imm b = 0x1`
            6. `add b s` (`b = b + s`)
            7. `d = 0x49`
            8. 
        - values being compared (hex)
            ```
            a   b
            35  7e

            ```
