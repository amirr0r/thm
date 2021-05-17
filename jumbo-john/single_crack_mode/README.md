> word mangling (substitutions)

`john` can build it's own dictionary based on the information that it has been fed and uses a set of rules called "mangling rules"

We can use the **single crack mode** with the following arguments: `--single`

> **Note**: we need to change the file format that we're giving to `john` in order to create a wordlist 

```console
root@kali:~/thm/jumbo-john# hash-identifier                                    
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
 HASH: 7bf6d9bb82bed1302f331fc6b816aada                                                                                                                      
                                                                                                                                                             
Possible Hashs:                    
[+] MD5
...
root@kali:~/thm/jumbo-john# john --single --format=raw-MD5 single_crack_mode/single_crack_mode.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=12
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 2 candidates buffered for the current salt, minimum 24 needed for performance.
Warning: Only 20 candidates buffered for the current salt, minimum 24 needed for performance.
Warning: Only 5 candidates buffered for the current salt, minimum 24 needed for performance.
Jok3r            (joker)
1g 0:00:00:00 DONE (2021-05-17 11:00) 100.0g/s 19500p/s 19500c/s 19500C/s j0ker..J0k3r
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed

```