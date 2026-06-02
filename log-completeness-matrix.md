# HelpForge — Log Completeness Matrix

> Companion to Chapter 7 (*Logging Architecture & Instrumentation*). This maps
> every attack step of the HelpForge chain to its forensic log evidence, states
> whether that evidence exists **by default**, what configuration closes any
> gap, and records the **verified** log entry observed after running the
> autosolve (`solve.sh` / `autosolve.py`).

- **Target:** `192.168.56.102` (Ubuntu 22.04, GLPI 10.0.9)
- **Attacker host:** `192.168.56.1` (vboxnet0)
- **Verification method:** after one full `solve.sh 192.168.56.102` run, the
  relevant logs were read as `root` on the VM and the entry for each step was
  confirmed (lines quoted under *Verification Evidence*).
- **Steps mirror** the Attack Timeline in `writeup.md`, the MITRE mapping in
  `challenge-design-v1.md` 3.1, and the per-step rows in `logs/timing.csv`.
- **Baseline vs. shipped (important):** the *Logged by Default* column is judged
  against a **vanilla** Ubuntu 22.04 + standard-services baseline — this is the
  Chapter 7 gap analysis. The HelpForge **provisioning ships and applies the
  listed gap-closers automatically**: the `audit` Ansible role runs during
  `vagrant up` (auditd file/execve watches + MySQL `general_log`), and UFW
  logging is enabled by the `harden` role. So on the **delivered** VM, steps 5,
  6 and the server-side depth of step 10 are captured with **no manual steps**,
  as verified below. The *Partial/No (baseline)* verdicts therefore describe the
  teaching baseline, not a gap in the shipped machine.

---

## Matrix

| # | Attack Step (MITRE) | Expected Log Source (path) | Logged by Default | Config to Close Gap | Verified after solve.sh |
|---|---------------------|----------------------------|-------------------|---------------------|--------------------------|
| 1 | nmap service scan (T1046) | `/var/log/syslog` (UFW kernel block); also `/var/log/auth.log` (SSH banner grab) | **Yes** | — (UFW active, `Logging: on`) | ✅ `UFW BLOCK ... SRC=192.168.56.1 DST=192.168.56.102 ... DPT=3306` |
| 2 | HTTP/GLPI fingerprinting (T1595) | `/var/log/apache2/helpforge-access.log` | **Yes** | — | ✅ `GET /index.php HTTP/1.1" 200` from `192.168.56.1` |
| 3 | FTP anonymous enumeration (T1083) | `/var/log/vsftpd.log` | **Yes** | — | ✅ `OK DOWNLOAD: Client "192.168.56.1", "/client_logs_2024.tar.gz"` |
| 4 | GLPI CVE-2023-42802 RCE (T1190, T1505.003) | `/var/log/apache2/helpforge-access.log` | **Yes** | — | ✅ `POST /front/device.form.php" 200` + `GET /front/files/file.png" 200` |
| 5 | Read `config_db.php` via web shell (T1552.001) | HTTP: `/var/log/apache2/helpforge-access.log` · server-side file read: `/var/log/audit/audit.log` | **Partial** (baseline) | auditd watch `-w /var/www/glpi/config/config_db.php -p r -k glpi_dbconfig_read` — **shipped & applied automatically** by the `audit` role at `vagrant up` | ✅ HTTP: `GET /front/files/file.png?cmd=cat+%2F...%2Fconfig_db.php" 200` · ✅ server-side: `type=PATH name="/var/www/glpi/config/config_db.php" OUID="www-data" key="glpi_dbconfig_read"` |
| 6 | Query `glpi_users` bcrypt hash (T1005) | HTTP: `/var/log/apache2/helpforge-access.log` · DB-side: `/var/log/mysql/general.log` | **Partial** (baseline) | MySQL `general_log='ON'` — **shipped & applied automatically** by the `audit` role | ✅ HTTP: `GET /front/files/file.png?cmd=mysql+...SELECT+password+FROM+glpi_users..." 200` · ✅ DB-side: `general.log` → `Query SELECT password FROM glpi_users WHERE name='techops'` |
| 7 | Offline bcrypt cracking (T1110.002) | none (host-side, offline) | **No** | — (cannot be closed; see Gap Analysis) | ⛔ no target-side log — by design |
| 8 | SSH password reuse as `techops` (T1078) | `/var/log/auth.log` | **Yes** | — | ✅ `sshd: Accepted password for techops from 192.168.56.1 port ... ssh2` |
| 9 | `sudo -l` enumeration (T1069.001) | `/var/log/auth.log` | **No** | sudoers I/O logging / `Defaults log_allowed` (low value) | ❌ no entry — `sudo -n -l` listing is not logged by default (see Gap Analysis) |
| 10 | `sudo less` shell escape → root (T1548.003) | `/var/log/auth.log` (sudo command); root `execve` via `/var/log/audit/audit.log` | **Yes** | (server-side depth) auditd `-a always,exit -F arch=b64 -S execve -F euid=0 -k root_exec` — shipped automatically | ✅ `sudo: techops : ... USER=root ; COMMAND=/usr/bin/less /var/log/glpi/helpforge.log` · ✅ auditd `key="root_exec"` execve `euid=0` |

---

## Coverage Summary

| Verdict | Steps | Count |
|---------|-------|-------|
| Logged by default (**Yes**) | 1, 2, 3, 4, 8, 10 | 6 |
| Observable by default but server-side depth needs config (**Partial**) | 5, 6 | 2 |
| Not logged by default (**No**) | 7, 9 | 2 |

Two different metrics are at play — do not conflate them:

- **Breadth — observable by default (Yes + Partial): 8 / 10 = 80 %.** This is
  how many steps leave *any* default log trace, and it meets the ≥ 70 % target.
  (`Partial` still counts as observable: the action is visible at the HTTP
  layer, only the server-side view is missing.)
- **Depth — fully logged against a vanilla baseline (Yes only): 6 / 10 = 60 %.**
- The `audit` role (auditd file/execve watches + MySQL general log) moves steps 5
  and 6 from *Partial → Yes* by adding **server-side depth**. On HelpForge this
  role **runs automatically during `vagrant up`**, so the **delivered VM is
  already at the higher tier**: fully-logged **8 / 10 = 80 %** out of the box
  (verified). Breadth stays 80 %, because steps 5 and 6 already counted as
  observable.
- **Two steps stay unlogged even with the `audit` role applied:** step 7 (offline
  cracking — *unavoidable*, no target interaction) and step 9 (`sudo -l` — *not
  covered by these rules*; the sudoers watches are `-p wa`/write-only and do not
  catch the read that `sudo -l` performs). Reaching 9 / 10 would additionally
  require making `sudo -l` loggable (`Defaults log_allowed`, or a read watch on
  sudoers); **10 / 10 is impossible** because step 7 cannot, in principle,
  produce a target-side log.

---

## Verification Evidence (real lines from this run)

Captured as root on `192.168.56.102` after **one** `solve.sh 192.168.56.102` run.
All lines below are from that **same run** (Jun 1 23:14:37–23:15:00 UTC), which is
the run recorded in `logs/timing.csv` (epoch window `1780355675`–`1780355701`):

```text
# Step 1 — /var/log/syslog (UFW active: Status: active / Logging: on)
Jun  1 23:14:37 ubuntu-jammy kernel: [UFW BLOCK] IN=enp0s8 SRC=192.168.56.1 DST=192.168.56.102 PROTO=TCP SPT=36954 DPT=3306 SYN

# Step 3 — /var/log/vsftpd.log
Mon Jun  1 23:14:53 2026 [pid 20807] [ftp] OK DOWNLOAD: Client "192.168.56.1", "/client_logs_2024.tar.gz", 2975 bytes

# Steps 2/4/5/6 (HTTP layer) — /var/log/apache2/helpforge-access.log  (NOTE: the default access.log is empty; the GLPI vhost logs here)
192.168.56.1 - - [01/Jun/2026:23:14:53 +0000] "POST /front/device.form.php HTTP/1.1" 200 6040 "-" "HelpForge-Autosolve/1.0"
192.168.56.1 - - [01/Jun/2026:23:14:53 +0000] "GET /front/files/file.png HTTP/1.1" 200 293 "-" "HelpForge-Autosolve/1.0"
192.168.56.1 - - [01/Jun/2026:23:14:53 +0000] "GET /front/files/file.png?cmd=cat+%2Fvar%2Fwww%2Fglpi%2Fconfig%2Fconfig_db.php HTTP/1.1" 200 620
192.168.56.1 - - [01/Jun/2026:23:14:53 +0000] "GET /front/files/file.png?cmd=mysql+...+SELECT+password+FROM+glpi_users+WHERE+name%3D...techops...%3B HTTP/1.1" 200 436

# Step 5 (server-side) — /var/log/audit/audit.log  (auditd watch, shipped automatically)
type=PATH msg=audit(1780355693.548:629): name="/var/www/glpi/config/config_db.php" inode=559017 mode=0100664 OUID="www-data" OGID="www-data"   key="glpi_dbconfig_read"
#   note: audit timestamp 1780355693.548 matches step 5 end_ms 1780355693549 in logs/timing.csv

# Step 6 (server-side) — /var/log/mysql/general.log  (general_log=ON, shipped automatically)
2026-06-01T23:14:53.561994Z   47 Query   SELECT password FROM glpi_users WHERE name='techops'

# Step 8 — /var/log/auth.log
Jun  1 23:14:57 ubuntu-jammy sshd[20818]: Accepted password for techops from 192.168.56.1 port 46970 ssh2

# Step 10 — /var/log/auth.log + /var/log/audit/audit.log
Jun  1 23:15:00 ubuntu-jammy sudo:  techops : TTY=pts/0 ; PWD=/home/techops ; USER=root ; COMMAND=/usr/bin/less /var/log/glpi/helpforge.log
Jun  1 23:15:00 ubuntu-jammy sudo: pam_unix(sudo:session): session opened for user root(uid=0) by techops(uid=1002)
type=SYSCALL ... syscall=execve ... euid=0 ... key="root_exec"
```

Observed environment state on the **freshly provisioned** VM (after `vagrant up`,
no manual steps) — this is what makes steps 5, 6 and the server-side depth of 10
captured on the delivered machine:

```text
auditd:                active, enabled at boot; 4 rules loaded (auditctl -l)
/var/log/audit/audit.log:  present; keys observed → glpi_dbconfig_read, sudoers_change, root_exec
/var/log/mysql/general.log: present; general_log = ON
UFW:                   active, Logging: on (low)
/var/log/apache2/:     access.log = 0 bytes;  helpforge-access.log = populated (GLPI vhost)
```

---

## Gap Analysis (steps not logged by default)

### Step 7 — Offline bcrypt cracking (T1110.002) · gap is **unavoidable**
The `techops` bcrypt hash is cracked on the **attacker's** machine against the
FTP wordlist. No interaction with the target occurs during cracking, so the
target cannot, even in principle, produce a log for it. This is an inherent
property of offline credential attacks, not a configuration shortfall. It is
**non-critical for detection** because the surrounding steps are observable: the
hash source (step 6, MySQL query through the web shell) and the *result* of the
crack (step 8, a successful SSH login as `techops` from the same attacker IP
that exploited the web app minutes earlier) are both logged. The crack is
detectable by **correlation**, not by a direct artifact.

### Step 9 — `sudo -l` enumeration (T1069.001) · gap is **non-critical**
`sudo -n -l` only *lists* the invoking user's allowed commands; it executes
nothing as root. Verification confirmed it produced **no** `auth.log` entry on
the default install. This is low-value to lose: it is passive reconnaissance,
and the action it enables — the actual privileged command in step 10 — **is**
fully logged (`sudo: techops ... COMMAND=/usr/bin/less ...`). The privilege
escalation therefore has no blind spot even though the preceding enumeration is
silent. It can be made visible with sudoers logging (`Defaults log_allowed`) if
desired, but the detection value does not justify the added noise.

### Steps 5 & 6 — `Partial` rationale
Both actions are issued **through the web shell**, so the command itself
(`cat .../config_db.php`, the `mysql ... SELECT ... FROM glpi_users`) is fully
visible in `helpforge-access.log` by default — the step is observable. What is
*not* captured **on a vanilla baseline** is the **server-side** view: the actual
file-read syscall (needs auditd) and the actual SQL executed by MySQL (needs
`general_log`). The Ansible `audit` role adds both and **runs automatically
during `vagrant up`**, so on the delivered VM these are fully logged (verified
above), enabling the "web shell read → DB query" correlation described in
Chapter 7.

---

## Closing the Gaps (configuration)

Provided by the `audit` Ansible role (`ansible/roles/audit/`), which **runs
automatically during `vagrant up`** so the VM is ready for log collection with no
manual steps. (`./audit.sh` only re-applies the same role on an
already-running VM.)

```ini
# /etc/audit/rules.d/helpforge.rules
-w /var/www/glpi/config/config_db.php -p r -k glpi_dbconfig_read   # step 5 server-side
-w /etc/sudoers      -p wa -k sudoers_change
-w /etc/sudoers.d/   -p wa -k sudoers_change
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_exec        # step 10 root execve
```

```sql
-- MySQL general query log (step 6 DB-side)
SET GLOBAL general_log_file='/var/log/mysql/general.log';
SET GLOBAL general_log='ON';
```

Because this role runs automatically at `vagrant up`, the **delivered VM already
sits at the higher tier**: steps 5 and 6 are *Yes* server-side and step 10 has
its `execve` depth — **8/10 = 80 % fully logged out of the box** (verified on the
freshly built VM). Two steps remain unlogged: step 7 (offline cracking —
unavoidable) and step 9 (`sudo -l` — not covered by these rules, since the
sudoers watches are write-only). Reaching 9/10 would additionally require logging
`sudo -l` (e.g. `Defaults log_allowed`); 10/10 is impossible because step 7
produces no target-side artifact by nature.
