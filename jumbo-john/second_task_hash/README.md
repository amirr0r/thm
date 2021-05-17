`NTHash` is the hash format that modern Windows Operating System machines will use.
`NTLM` is the previous version of Windows format for hashing passwords.

We can acquire NTHash/NTLM hashes by two ways:
- dumping the **SAM database** on a Windows machine, by using a tool like Mimikatz
- from the **Active Directory database**: `NTDS.dit`.

```console
root@kali:~/thm/jumbo-john/second_task_hash# john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt second_task_hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=12
Press 'q' or Ctrl-C to abort, almost any other key for status
mushroom         (?)
1g 0:00:00:00 DONE (2021-05-17 09:15) 100.0g/s 307200p/s 307200c/s 307200C/s skater1..dangerous
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed
```
