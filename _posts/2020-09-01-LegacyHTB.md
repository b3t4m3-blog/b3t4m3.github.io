---
title: "HackTheBox — Legacy Writeup"
date: 2020-09-02 12:06:00 +0530
categories: [HackTheBox,Windows Machines]
tags: [masscan, legacy, XP, SMB, ms08-67, ms17-010, shellcode, whoami, smbserver, metasploit, ms08_067_netapi]
image: /assets/img/Posts/Legacy.png
---

> Legacy from HackTheBox is an retired machine which is vulnerable to infamous MS08-067 & MS17-010 SMB vulnerabilities which can be easily exploited with publicly available scripts and Metasploit.

>We will use three different methods to pwn the box. First, we will use MS08-067 exploit, then MS17-010 exploit and last we will use Metasploit for automatic exploitation.

# Recon

## nmap

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-12 18:40 CST
Nmap scan report for 10.10.10.4
Host is up (0.096s latency).

PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h27m32s, deviation: 2h07m16s, median: 4d22h57m32s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:07:a4 (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2022-07-18T05:38:03+03:00

Servic1e detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.56 seconds
```


## crackmapexec

![3acbc783daf14309f09312d0da1fcbe8.png](/assets/img/Posts/3acbc783daf14309f09312d0da1fcbe8.png)

##  MS17-010, spoolss - browser OK
https://github.com/helviojunior/MS17-010

![8d340c4e7b37e377a03894a78ad596f7.png](/assets/img/Posts/8d340c4e7b37e377a03894a78ad596f7.png)



![8514e19dfcf543cd17b7d3e4f699276c.png](/assets/img/Posts/8514e19dfcf543cd17b7d3e4f699276c.png)

## send_and_execute


![021e33b3255e2cc8875595d5b6b42dcb.png](/assets/img/Posts/021e33b3255e2cc8875595d5b6b42dcb.png)

## root 
![b2f93e953e49b688169992a6ad32ca12.png](/assets/img/Posts/b2f93e953e49b688169992a6ad32ca12.png)

# MS08-067

![35f60812453e1d212e899ccd3f804b49.png](/assets/img/Posts/35f60812453e1d212e899ccd3f804b49.png)

```
IDs:  CVE:CVE-2008-4250
```

```
The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
code via a crafted RPC request that triggers the overflow during path canonicalization.
```


![a15c4b7af222563d37543380272195d7.png](/assets/img/Posts/a15c4b7af222563d37543380272195d7.png)

## msfvenom


![c469575657e3f630cca6318d5230fa40.png](/assets/img/Posts/c469575657e3f630cca6318d5230fa40.png)


![dd549394dd7b9fa759c5aa5fd4337335.png](/assets/img/Posts/dd549394dd7b9fa759c5aa5fd4337335.png)
