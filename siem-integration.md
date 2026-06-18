# HelpForge — SIEM Integration (Chapter 8)

This is the HelpForge adaptation of Chapter 8 (*SIEM Integration with Elastic
Stack*). The course example targets DevDrop (WordPress); HelpForge runs GLPI, a
custom Apache vhost log, and an anonymous-FTP rabbit hole, so the integrations,
ingest pipelines and queries below are adapted accordingly.

Companion to `log-completeness-matrix.md` (Chapter 7). That document proves the
**raw logs** exist on the VM; this one ships them into Elasticsearch and makes
every attack step queryable in Kibana.

> **Live, screenshot-backed results:** see **`siem-analytics-writeup.md`** —
> a full replay verified on 2026-06-17 (`verify_siem.py` 30/30) with one Kibana
> Discover screenshot per attack step in `siem-screenshots/`.

## Architecture

```text
Host 192.168.56.1
├── elastic-stack/  → ELK Server VM  192.168.56.10  (6 GB)
│     Elasticsearch :9200   Kibana :5601   Fleet Server :8220
│     + HelpForge-Policy, integrations, ingest pipelines (siem_content role)
└── helpforge/      → HelpForge CTF VM 192.168.56.102 (2 GB)
      Elastic Agent (Fleet-managed) ── System, Apache, MySQL integrations
      Filebeat (standalone)         ── MySQL general log, auditd, vsftpd
```

Elastic version **8.12.0** throughout. Deployment Option A (dedicated Vagrant VM).

## Bring-up order

The ELK server must exist first so its Fleet enrollment token can be handed to
HelpForge.

```bash
cd elastic-stack/ && vagrant up        # 1. SIEM stack (8–12 min first run)
                                       #    writes ./fleet-enrollment-token.txt
cd ../helpforge/  && vagrant up        # 2. CTF VM; elastic_agent role reads the
                                       #    token and Fleet-enrolls automatically
```

If HelpForge was already up before the stack existed:

```bash
cd elastic-stack/ && vagrant up
cd ../helpforge/  && vagrant provision --provision-with ansible   # or: --tags siem
```

The token handoff is automatic: `elastic-stack` writes the HelpForge enrollment
token to `elastic-stack/fleet-enrollment-token.txt` (a synced folder), and
`helpforge/Vagrantfile` reads it (or `HELPFORGE_FLEET_TOKEN`). With no token the
`elastic_agent` role is a **no-op**, so the challenge still provisions standalone
for shipping to a cross-solving partner.

## Log sources → collectors → data streams

| HelpForge log | Path | Steps | Collector | Data stream / filter | Parsing |
|---|---|---|---|---|---|
| syslog (UFW) | `/var/log/syslog` | 1 | Agent · System | `system.syslog` | built-in |
| auth.log | `/var/log/auth.log` | 8, 10 | Agent · System | `system.auth` | built-in (ECS) |
| Apache GLPI vhost | `/var/log/apache2/helpforge-access.log` | 2,4,5,6 | Agent · Apache (**custom path**) | `apache.access` | built-in (ECS) |
| MySQL error | `/var/log/mysql/error.log` | — | Agent · MySQL | `mysql.error` | built-in |
| MySQL general | `/var/log/mysql/general.log` | 6 | Filebeat | `data_stream.dataset: mysql.query` | `mysql-query-parse` |
| auditd | `/var/log/audit/audit.log` | 5,9,10 | Filebeat | `data_stream.dataset: auditd.log` | raw (message patterns) |
| vsftpd | `/var/log/vsftpd.log` | 3 | Filebeat | `data_stream.dataset: vsftpd.log` | `vsftpd-parse` |

> **Note (field consistency):** every source carries **`data_stream.dataset`** —
> the Fleet Agent sets it natively, and the standalone Filebeat sets it via each
> input's `data_stream.*` fields and writes to real data streams
> (`logs-<dataset>-default`, pre-created by the `siem_content` role). So all
> queries filter uniformly on `data_stream.dataset` (`apache.access`,
> `system.auth`, `mysql.query`, `vsftpd.log`, `auditd.log`). The ingest pipelines
> additionally set `event.dataset`; auditd is shipped raw (no pipeline), so query
> its contents by message text within `data_stream.dataset: "auditd.log"`.

## Attack-step → KQL (Kibana Discover, data view `logs-*`)

| # | Step (MITRE) | KQL |
|---|---|---|
| 1 | Recon nmap (T1046) | `data_stream.dataset: "system.syslog" and message: "UFW BLOCK" and message: "DPT=3306"` |
| 2 | GLPI fingerprint (T1595) | `data_stream.dataset: "apache.access" and url.path: "/index.php" and source.ip: "192.168.56.1"` |
| 3 | FTP enum (T1083) | `data_stream.dataset: "vsftpd.log" and file.path: *client_logs_2024*` |
| 4 | **CVE-2023-42802 RCE (T1190/T1505.003)** | `data_stream.dataset: "apache.access" and url.original: *device.form.php* and http.request.method: "POST"` then the trigger `url.original: *file.png*` |
| 5 | Read config_db.php (T1552.001) | HTTP: `data_stream.dataset: "apache.access" and url.original: *config_db.php*` · server-side: `data_stream.dataset: "auditd.log" and message: "glpi_dbconfig_read"` |
| 6 | Dump glpi_users hash (T1005) | `data_stream.dataset: "mysql.query" and message: "glpi_users"` |
| 7 | Offline bcrypt crack (T1110.002) | *no target log by design* — see correlation below |
| 8 | SSH reuse as techops (T1078) | `data_stream.dataset: "system.auth" and event.action: "ssh_login" and event.outcome: "success" and user.name: "techops"` |
| 9 | `sudo -l` recon (T1069.001) | `data_stream.dataset: "auditd.log" and message: "type=EXECVE" and message: "a0=\"sudo\"" and message: "-l"` |
| 10 | sudo less → root (T1548.003) | `data_stream.dataset: "system.auth" and message: "COMMAND=/usr/bin/less"` · auditd `data_stream.dataset: "auditd.log" and message: "root_exec"` |

**Key event (Milestone item 7):** the GLPI CVE-2023-42802 web-shell upload and
execution — Query 4. If `POST /front/device.form.php` (200) followed by
`GET /front/files/file.png?cmd=...` is visible in Discover, the integration is
proven.

**Correlation (covers the unloggable step 7):** pivot on the attacker IP across
every source —

```text
source.ip: "192.168.56.1"
```

Sort by `@timestamp` ascending → the full chain appears: UFW block → GLPI HTTP →
FTP download → RCE → MySQL hash query → SSH accept → sudo less. The offline
crack (step 7) leaves no line, but it is bracketed by the hash dump (step 6) and
the successful `techops` login (step 8) from the same IP minutes later.

## The `sudo -l` blind spot — closed for Exercise 4

Chapter 8 Exercise 4 ("The Invisible Command") makes `sudo -l` visible via
auditd `execve`. HelpForge's Chapter 7 `root_exec` rule filters `-F euid=0`, so
`sudo -l` (run as `techops`, euid ≠ 0) was **not** caught — matching the
"step 9 = No" verdict in the completeness matrix. The `audit` role now also
ships:

```ini
-w /usr/bin/sudo -p x -k sudo_exec   # every sudo invocation, any euid
```

The `-w /usr/bin/sudo -p x` watch causes every sudo invocation's `execve` to be
audited, so the readable command appears in the **EXECVE** record. `autosolve.py`
runs `sudo -n -l`, yielding `type=EXECVE … argc=3 a0="sudo" a1="-n" a2="-l"`
(verified in a real run). Query 9 matches that record (`a0="sudo"` + `-l`), since
`-l` may sit in `a1` or `a2`. Note the `sudo_exec` *key* itself is recorded only
once — on the rule-registration (`CONFIG_CHANGE`) event, not on each execution —
so detection keys off the EXECVE argv, exactly as Chapter 8 Exercise 4 does.

## Milestone checklist (8.15) for HelpForge

- [ ] Elastic Stack up: `vagrant ssh -c "systemctl is-active elasticsearch kibana elastic-agent"` (elastic-stack) → 3× `active`
- [ ] `curl -u elastic:changeme http://192.168.56.10:9200` → `"cluster_name":"helpforge-siem","status":"green|yellow"`
- [ ] Elastic Agent on HelpForge shows **Healthy** in Fleet → Agents
- [ ] Integrations on HelpForge-Policy: **System, Apache (custom path), MySQL**
- [ ] Standalone Filebeat running on HelpForge: `systemctl is-active filebeat`
- [ ] Ingest pipelines exist: `mysql-query-parse`, `vsftpd-parse`
- [ ] Data streams present (run a `solve.sh` replay first): `system.auth`, `system.syslog`, `apache.access`, `apache.error`, `mysql.error`, `logs-mysql.query-default`, `logs-auditd.log-default`, `logs-vsftpd.log-default`
- [ ] Key event (Query 4) visible and queryable in Discover

**Final validation:** `cd helpforge && ./solve.sh 192.168.56.102`, wait ~60 s
for ingestion, then run Query 4 (and the `source.ip` correlation) in Discover.

The whole checklist above is automated by the verifier (run from the host):

```bash
cd elastic-stack && python3 scripts/verify_siem.py
```

It checks ES/Kibana/Fleet health, the pipelines, the three pre-created data
streams, the System/Apache/MySQL integrations (incl. the custom Apache path), and
counts events for each attack step. Per-step counts are warnings until a
`solve.sh` replay has been ingested; it exits non-zero on any hard failure.

## Troubleshooting (HelpForge specifics)

- **Apache data stream empty but the site works** — the default `access.log` is
  0 bytes; GLPI logs to `helpforge-access.log`. Confirm the Apache integration
  path is `/var/log/apache2/helpforge-access.log` (UI: Fleet → HelpForge-Policy
  → Apache → access log path).
- **`logs-mysql.query-default` empty** — the MySQL general log must be on
  (`audit` role does this): `vagrant ssh -c "sudo grep -c '' /var/log/mysql/general.log"`. Filebeat registry stuck: `sudo rm -rf /var/lib/filebeat/registry && sudo systemctl restart filebeat`.
- **vsftpd events unparsed** (`event.action` empty) — check the pipeline exists:
  `curl -s -u elastic:changeme http://192.168.56.10:9200/_ingest/pipeline/vsftpd-parse`.
- **Agent "Offline"** — HelpForge can't reach Fleet. From HelpForge:
  `curl http://192.168.56.10:8220/api/status` should return `"status":"HEALTHY"`.
  Bring up `elastic-stack` first.
- **Nothing in Discover** — time picker defaults to *Last 15 minutes*; set it to
  *Last 7 days* (or your replay window).
