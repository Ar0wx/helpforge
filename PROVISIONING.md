# HelpForge Provisioning

This repository provisions the HelpForge CTF VM with Vagrant and Ansible.

## Requirements

- Vagrant 2.4.x or newer
- VirtualBox provider
- Internet access during provisioning for official Ubuntu packages and the GLPI
  10.0.9 release archive

If VirtualBox reports that VT-x is already used by another hypervisor on Linux,
unload the KVM modules before starting the VM:

```bash
sudo modprobe -r kvm_intel kvm
```

## Fresh End-to-End Build

From the repository root:

```bash
vagrant destroy -f
./build.sh
./verify.sh
```

Expected result:

- `./build.sh` completes the Vagrant and Ansible provisioning run.
- `./verify.sh` ends with `failed=0`.
- The web application is reachable at `http://192.168.56.102/`.

Optional quick checks:

```bash
curl -I http://192.168.56.102/
nmap -sV -p21,22,80,3306 192.168.56.102
```

## Optional Detection Setup

The audit role enables additional logging for detection-engineering exercises:

```bash
./audit.sh
```

## Autosolve

The repository includes an autosolve script for the final solution chain:

```bash
./solve.sh 192.168.56.102
```

On native Windows, install the SSH dependency first and run the Python script
directly:

```powershell
py -m pip install paramiko
py autosolve.py 192.168.56.102
```

The script performs the intended path automatically: GLPI CVE exploitation,
database credential extraction, `techops` hash recovery, FTP wordlist cracking,
SSH login, and `sudo less` privilege escalation.

## Secure Everything Else / Version Stability

The challenge intentionally keeps GLPI at version 10.0.9 for
`CVE-2023-42802`. GLPI is installed from the fixed upstream release archive and
is not managed through `apt`, so normal package upgrades cannot silently replace
it with a patched GLPI version.

The provisioning also disables automatic package upgrades:

- `unattended-upgrades` is stopped and disabled.
- `apt-daily` and `apt-daily-upgrade` timers are disabled and masked.
- `/etc/apt/apt.conf.d/20auto-upgrades` disables periodic apt updates and
  unattended upgrades.

The hardening role then marks challenge-relevant packages as held with
`apt-mark hold`, including Apache, PHP 8.1 packages, MySQL, vsftpd, OpenSSH,
sudo, and less. This prevents an accidental `apt upgrade` from changing the
runtime components that the challenge depends on.

Manual validation commands inside the VM:

```bash
apt-mark showhold
systemctl is-enabled unattended-upgrades || true
systemctl is-enabled apt-daily.timer apt-daily-upgrade.timer || true
```

## Final Cleanup Before Export

Run cleanup only after validation and before exporting or submitting the final
VM state:

```bash
./cleanup.sh
```

The cleanup role removes provisioning leftovers and shell history artifacts.
