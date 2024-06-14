# Race Condition Lectures

[TOC]

## Background

- Olden days: single core CPUs
- Modern times:
    - Multi-core, but still fewer cores than processes: the kernel decides what processes to "schedule" when
    - Limited-channel memory controllers (i.e., quad-channel memory)
    - Limited-channel storage media
    - Single-channel network communication
- Bottom line: Bottlenecks in computing architecture cause concurrent events to be at least partially serialized
- Without implicit dependencies or explicit effort by the program, the execution order is only guaranteed within a process (really, within a thread)

### TOCTOU: Time of Check / Time of Use

- Some execution orderings can be **buggy**: `P1`'s `do_action()` might be taking actions in a changed world from the one examined by `check_input()`
    ```c
    P1 check_input()
    P2 check_input()
    P2 do_action() <-- might have changed the world
    P1 do_action()
    ```

- Abusing concurrency errors requires *racing* to carefully impact the state of an application during a weak point. Hence: **Race Condition**
    ```c
    P1 check_input()
    WEAK POINT
    P1 do_action()
    ```

### History

- Race condition were originally discussed in a *hardware* context: in 1954, David Huffman, of Huffman Encoding fame, wrote about them in his PhD dissertation, "The Synthesis of Sequential Switching Circuits".

## Races in the File System

## Processes and Threads

## Races in Memory

## Signals and Reentrancy
