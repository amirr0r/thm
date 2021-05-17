```console
root@kali:~/thm/jumbo-john/third_task_hash# cat third_task_hash.txt 
This is everything I managed to recover from the target machine before my computer crashed... See if you can crack the hash so we can at least salvage a password to try and get back in.

root:x:0:0::/root:/bin/bash
root:$6$Ha.d5nGupBm29pYr$yugXSk24ZljLTAZZagtGwpSQhb3F2DOJtnHrvk7HI2ma4GsuioHp8sm3LJiRJpKfIf7lZQ29qgtH17Q/JDpYM/:18576::::::

root@kali:~/thm/jumbo-john/third_task_hash# cat > passwd
root:x:0:0::/root:/bin/bash
^C
root@kali:~/thm/jumbo-john/third_task_hash# cat > shadow
root:$6$Ha.d5nGupBm29pYr$yugXSk24ZljLTAZZagtGwpSQhb3F2DOJtnHrvk7HI2ma4GsuioHp8sm3LJiRJpKfIf7lZQ29qgtH17Q/JDpYM/:18576::::::

^C
root@kali:~/thm/jumbo-john/third_task_hash# vim shadow 
root@kali:~/thm/jumbo-john/third_task_hash# unshadow passwd shadow > unshadowed.txt
root@kali:~/thm/jumbo-john/third_task_hash# john unshadowed.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 12 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 18 candidates buffered for the current salt, minimum 48 needed for performance.
Warning: Only 30 candidates buffered for the current salt, minimum 48 needed for performance.
Warning: Only 36 candidates buffered for the current salt, minimum 48 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 20 candidates buffered for the current salt, minimum 48 needed for performance.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
1234             (root)
1g 0:00:00:00 DONE 2/3 (2021-05-17 09:24) 4.166g/s 9916p/s 9916c/s 9916C/s 123456..keeper
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
