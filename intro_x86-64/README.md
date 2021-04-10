# Intro x86-64

## Introduction

### radare2

`r2 -d <binary>`

- `aa`: analyze all symbols and entry points in the executable 
- `e asm.syntax=<intel|att>`: set syntax
- `afl`: analize functions (list them all)
- `pdf @<function_name>`: print disassembly function
- `db <address>`: setting a break point
- `dc`: continue execution
- `dr`: display CPU registers
- `ds`: continue to the next instruction
- `afvd`: **a**nalyze **f**unction **v**ariables **d**isplay
- `px @<address_or_register>`: hexdump of N bytes (o=octal, w=32bit, q=64bit)

### Registers

Manipulating CPU registers because:

- transfer data between memory and register, and vice versa
- perform arithmetic operations on registers and data
- delegate control to other parts of the program

- `rsp` is the **stack pointer** and it points to the **top of the stack**_(most recent memory address)_.
- `rbp` is the **frame pointer** and points to the frame of the function currently being executed

> every function is executed in a new frame

### Assembly instructions (AT&T)

The last letter of the instructions represents the size of the data:

Intel Data Type      | Suffix | Size(bytes) |
---------------------|--------|-------------|
**Byte**             | `b`    | 1           |
**Word**             | `w`    | 2           |
**Double Word**      | `l`    | 4           |
**Quad Word**        | `q`    | 8           |
**Single Precision** | `s`    | 4           |
**Double Precision** | `l`    | 8           |

- `mov<letter> source, destination`
- `add<letter> source, destination`
- `sub<letter> source, destination`
- `imul<letter> source, destination` destination = destination * source
- `xor<letter> source, destination`
- `and<letter> source, destination`
- `or<letter> source, destination`
- `salq source, destination`: destination = destination `<<` source (`<<` is the left bit shifting operator)
- `sarq source, destination`: destination = destination `>>` source (`>>` is the right bit shifting operator)
- `leaq source, destination`: this instruction sets destination to the address denoted by the expression in source

___

## Comparison

- `cmpq source2, source1`: computing `a - b`
- `testq source2, source1`: computing `a & b`
- **jump**: 
    + `jmp`: unconditional
    + `je`: equal
    + `jne`: not equal
    + `jg`: greater 
    + `jge`: greater or equal
    + `jl`: less
    + `jle`: less or equal
    + `js`: negative
    + `jns`: non negative
    + `ja`: above (unsigned)
    + `jb`: below (unsigned)

Loops are just if statements and jump.

## Useful links

- <http://web.mit.edu/rhel-doc/3/rhel-as-en-3/i386-syntax.html>
- <https://github.com/radareorg/radare2/blob/master/doc/intro.md#radare2>
- <https://gist.github.com/williballenthin/6857590dab3e2a6559d7#radare2>
- <https://web.archive.org/web/20180312191821/http://www.radare.org/get/THC2018.pdf>
- <https://stackoverflow.com/questions/41372971/can-radare2-print-local-variables-by-name>