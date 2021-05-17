```console
root@kali:~/thm/jumbo-john/Cracking a_Password_Protected_Zip_File # zip2john password_protected_zip_file.zip > zip.john
ver 1.0 efh 5455 efh 7875 password_protected_zip_file.zip/zippy/flag.txt PKZIP Encr: 2b chk, TS_chk, cmplen=38, decmplen=26, crc=849AB5A6
root@kali:~/thm/jumbo-john/Cracking a_Password_Protected_Zip_File # john zip.john 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 12 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 11 candidates buffered for the current salt, minimum 12 needed for performance.
Warning: Only 2 candidates buffered for the current salt, minimum 12 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 9 candidates buffered for the current salt, minimum 12 needed for performance.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
Proceeding with incremental:ASCII
pass123          (password_protected_zip_file.zip/zippy/flag.txt)
1g 0:00:00:02 DONE 3/3 (2021-05-17 11:25) 0.4237g/s 2347Kp/s 2347Kc/s 2347KC/s mnmj..pace103
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

___

```console
root@kali:~/thm/jumbo-john/Cracking a_Password_Protected_archive # rar2john password_protected.rar > rar.john
root@kali:~/thm/jumbo-john/Cracking a_Password_Protected_archive # john rar.john 
Using default input encoding: UTF-8                                           
Loaded 1 password hash (RAR5 [PBKDF2-SHA256 256/256 AVX2 8x])                 
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 12 OpenMP threads                                                                                                                                   
Proceeding with single, rules:Single                                          
Press 'q' or Ctrl-C to abort, almost any other key for status
password         (password_protected.rar)
1g 0:00:00:00 DONE 1/3 (2021-05-17 11:30) 16.66g/s 1600p/s 1600c/s 1600C/s password_protected.rar..Rar.detcetorp_drowssapdetcetorp
Use the "--show" option to display all of the cracked passwords reliably
Session completed  
```