---
layout: post
title: Hack The Box - Wifinetic Writeup
date: 2024-07-20 02:00:00 +0100
published: true
categories: [Hack The Box]
tags: [Hack The Box]
---

![valentineBadge.png](/assets/img/Wifinetic/wifineticBadge.png)

## Summary

By using anonymous login, I was able to access `ftp` server. There are several files listed there, so I downloaded them to my local machine for further inspection. Most interesting file is `backup-OpenWrt-2023-07-26.tar`. After extracting backup file, I got access to `/etc/` directory. By inspecting contents of files inside, I found valid credentials that allowed me to `ssh` into the system as user `netadmin`. While enumerating system as user `netadmin` I discovered wireless interfaces and used `iwconfig` to display more information about them. One of these interfaces, namely `mon0`, was in monitor mode. This can be exploited by doing WPS brute-force. To perform this attack we need wireless interface in monitoring mode (`mon0`) and BSSID of the Access Point. To obtain BSSID, I used `iw dev` command. 
I was able to perform this attack using `reaver` tool, which was pre-installed on the system. A successful attack resulted in obtaining WPA password, which can be used to gain root access to the system.

## Reconnaissance

### Nmap

```bash
nmap -sV -sC -p- -oN ./nmapAll.txt --max-retries=1 10.10.11.247
```

```
PORT   STATE SERVICE    VERSION
21/tcp open  ftp        vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.13
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp          4434 Jul 31  2023 MigrateOpenWrt.txt
| -rw-r--r--    1 ftp      ftp       2501210 Jul 31  2023 ProjectGreatMigration.pdf
| -rw-r--r--    1 ftp      ftp         60857 Jul 31  2023 ProjectOpenWRT.pdf
| -rw-r--r--    1 ftp      ftp         40960 Sep 11  2023 backup-OpenWrt-2023-07-26.tar
|_-rw-r--r--    1 ftp      ftp         52946 Jul 31  2023 employees_wellness.pdf
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
53/tcp open  tcpwrapped
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeration

### Service Enumeration

| **IP Address** | **Ports Open** |
|-------|--------|
| 10.10.11.180 | **TCP**: 22, 80, 443 |

#### Port 21

Anonymous access is allowed so I was able to log in. 

```bash
ftp anonymous@10.10.11.247
```

![ftp.png](/assets/img/Wifinetic/ftp.png)

By inspecting documents, I collected several usernames that could come in handy later.

```
HR Manager
samantha.wood93@wifinetic.htb
```

```
Oliver Walker
Wireless Network Administrator
olivia.walker17@wifinetic.htb
```

More interesting is `OpenWrt` backup file.
##### Backup archive 

After extracting `.tar` archive I was presented with these files:

![etc2.png](/assets/img/Wifinetic/etc2.png)

`passwd` file immediately caught my attention because it could contain valid accounts. We can see that there is only one account that looks interesting and it is `netadmin`. 

![etcPasswd.png](/assets/img/Wifinetic/etcPasswd.png)

By analyzing files in `/etc/config` directory, I found plaintext password in `wireless` file.  

![configWirteless2.png](/assets/img/Wifinetic/configWirteless2.png)

```
VeRyUniUqWiFIPasswrd1!
```

## Exploitation

### Initial Foothold

The credentials discovered during the enumeration phase are valid for `SSH` access to the system. 

```
netadmin : VeRyUniUqWiFIPasswrd1!
```

![sshLogin.png](/assets/img/Wifinetic/sshLogin.png)

## Post Exploitation

### Information Gathering

I used `ip` command to display all network interfaces which revealed multiple wireless interfaces.

```bash
ip addr
```

![ipaddr.png](/assets/img/Wifinetic/ipaddr.png)

I used `iwconfig` to display more information related to wireless interfaces. 

```bash
iwconfig
```

![iwconfig.png](/assets/img/Wifinetic/iwconfig.png)

It is worth noting that the `mon0` interface is in monitor mode. Monitor mode allows `wifi` interface to monitor all traffic on the wireless network. 

### Privilege Escalation

#### WPS Bruteforce

To perform this attack, I used tool called `reaver` which was already installed on system. In order to successfully perform this attack we need few things. First we need to specify interface which is in monitoring mode (`mon0`) and BSSID of the Access Point. To obtain BSSID, I used `iw dev` command.

```bash
iw dev
```

![iwdev2.png](/assets/img/Wifinetic/iwdev2.png)

Now with all information needed we can perform the attack.

```bash
reaver -i mon0 -b 02:00:00:00:00:00
```

![reaver.png](/assets/img/Wifinetic/reaver.png)

Attack was successful and I obtained WPA password.

```
WhatIsRealAnDWhAtIsNot51121!
```

This password can be used to get root access to the system. 

![escalation.png](/assets/img/Wifinetic/escalation.png)

### Root Flag

![rootFlag.png](/assets/img/Wifinetic/rootFlag.png)