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
                    reg_6 = reg_6 or 0x8
                }
                if(reg2_val > reg1_val) {
                    reg_6 = reg_6 or 0x10
                }
                if(reg2_val == reg1_val) {
                    reg_6 = reg_6 or 0x4
                }
                if(reg2_val != reg1_val) {
                    reg_6 = reg_6 or 0x1
                }
                if(reg2_val == 0 && reg1_val == 0) {
                    reg_6 = reg_6 or 0x2
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
        