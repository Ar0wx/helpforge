# HelpForge Design Summary

This repository contains the automated Vagrant and Ansible implementation of
the HelpForge CTF challenge.

The implemented attack chain is:

```text
FTP/HTTP/SSH reconnaissance
-> GLPI 10.0.9 fingerprinting
-> CVE-2023-42802 remote code execution
-> www-data shell
-> GLPI database credentials in config_db.php
-> MySQL glpi_users bcrypt hash
-> password cracking and SSH reuse as techops
-> sudo less shell escape
-> root
```

The detailed challenge solution is documented separately in the writeup
submission ZIP. The runnable provisioning source of truth is the combination of
`Vagrantfile`, `ansible/playbook.yml`, the role tasks under `ansible/roles/`,
and the helper scripts documented in `PROVISIONING.md`.
