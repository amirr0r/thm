## Hash 1

```console
root@kali:~/thm/jumbo-john/first_task_hashes# cat hash1.txt 
2e728dd31fb5949bc39cac5a9f066498
root@kali:~/thm/jumbo-john/first_task_hashes# hash-identifier                  
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #  
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 2e728dd31fb5949bc39cac5a9f066498

Possible Hashs:
[+] MD5
...
root@kali:~/thm/jumbo-john/first_task_hashes# john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=12
Press 'q' or Ctrl-C to abort, almost any other key for status
biscuit          (?)
1g 0:00:00:00 DONE (2021-05-17 08:25) 50.00g/s 134400p/s 134400c/s 134400C/s skyblue..nugget
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

## Hash 2

```console
root@kali:~/thm/jumbo-john/first_task_hashes# cat hash2.txt 
1A732667F3917C0F4AA98BB13011B9090C6F8065
root@kali:~/thm/jumbo-john/first_task_hashes# hash-identifier 
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 1A732667F3917C0F4AA98BB13011B9090C6F8065
                                       
Possible Hashs:                                                               
[+] SHA-1
...
root@kali:~/thm/jumbo-john/first_task_hashes# john --format=Raw-SHA1 --wordlist=/usr/share/wordlists/rockyou.txt hash2.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=12
Press 'q' or Ctrl-C to abort, almost any other key for status
kangeroo         (?)
1g 0:00:00:00 DONE (2021-05-17 08:33) 100.0g/s 11714Kp/s 11714Kc/s 11714KC/s karate2..kalvin1
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed
```

## Hash 3

```console
root@kali:~/thm/jumbo-john/first_task_hashes# cat hash3.txt 
D7F4D3CCEE7ACD3DD7FAD3AC2BE2AAE9C44F4E9B7FB802D73136D4C53920140A
root@kali:~/thm/jumbo-john/first_task_hashes# hash-identifier                  
   #########################################################################                                                                                 
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #                                                                                 
   #                                                             By Zion3R #                                                                                 
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: D7F4D3CCEE7ACD3DD7FAD3AC2BE2AAE9C44F4E9B7FB802D73136D4C53920140A

Possible Hashs:
[+] SHA-256
...
root@kali:~/thm/jumbo-john/first_task_hashes# john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt hash3.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=12
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
microphone       (?)
1g 0:00:00:00 DONE (2021-05-17 08:34) 100.0g/s 19660Kp/s 19660Kc/s 19660KC/s 123456..piggy9
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed
```

## Hash 4

```console
root@kali:~/thm/jumbo-john/first_task_hashes# cat hash4.txt 
c5a60cc6bbba781c601c5402755ae1044bbf45b78d1183cbf2ca1c865b6c792cf3c6b87791344986c8a832a0f9ca8d0b4afd3d9421a149d57075e1b4e93f90bf
root@kali:~/thm/jumbo-john/first_task_hashes# hash-identifier 
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: c5a60cc6bbba781c601c5402755ae1044bbf45b78d1183cbf2ca1c865b6c792cf3c6b87791344986c8a832a0f9ca8d0b4afd3d9421a149d57075e1b4e93f90bf

Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
--------------------------------------------------
root@kali:~/thm/jumbo-john/first_task_hashes# john --format=whirlpool --wordlist=/usr/share/wordlists/rockyou.txt hash4.txt
Using default input encoding: UTF-8
Loaded 1 password hash (whirlpool [WHIRLPOOL 32/64])
Warning: poor OpenMP scalability for this hash type, consider --fork=12
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
colossal         (?)
1g 0:00:00:00 DONE (2021-05-17 09:00) 9.090g/s 6255Kp/s 6255Kc/s 6255KC/s eta123..blah2007
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

