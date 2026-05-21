# HelpForge

Repository: https://github.com/Ar0wx/helpforge

HelpForge is a Vagrant + Ansible provisioned CTF VM for the Advanced Security
Analytics course.

ByteWise Solutions used to run a small managed IT helpdesk platform named
HelpForge. The server is still online after the company dissolved. Your goal is
to assess the machine from the outside and recover both flags.

Target: `192.168.56.102`

## Requirements

- Vagrant
- VirtualBox
- Internet access during the first provisioning run
- Hardware virtualization enabled in BIOS/UEFI

On Windows, run Vagrant directly from PowerShell, CMD, or Git Bash. Do not run
Vagrant inside WSL for this VM.

## Quick Start

From the repository root:

```bash
./build.sh
```

This starts the VM with VirtualBox and runs the full Ansible provisioning.

If shell scripts are not available, run the equivalent command:

```bash
vagrant up --provider=virtualbox --provision
```

After provisioning, the target should be reachable at:

- `http://192.168.56.102/`
- `http://127.0.0.1:8082/`

## Verify

Run the verification playbook after provisioning:

```bash
./verify.sh
```

Expected result: the Ansible recap ends with `failed=0`.

Useful manual checks:

```bash
curl -I http://192.168.56.102/
nmap -sV -p21,22,80,3306 192.168.56.102
```

## Fresh Rebuild

To recreate the VM from scratch:

```bash
vagrant destroy -f
./build.sh
./verify.sh
```

## Autosolve

The autosolve script executes the full intended solution path:

Linux, macOS, or Git Bash:

```bash
./solve.sh 192.168.56.102
```

Windows PowerShell or CMD:

```powershell
py -m pip install paramiko
.\solve.bat 192.168.56.102
```

The script performs GLPI exploitation, database credential extraction, hash
recovery, SSH login, and the final privilege escalation.

## Manual Exploit Assets

The manual GLPI PoC files are included as `rce.py` and `shell.php.old`.
The payload uses the `.old` extension because some upload systems reject ZIP
archives containing `.php` files. `rce.py` automatically uses `shell.php.old`
when `shell.php` is not present.

## Scope

Rules:

- Treat the VM as the only in-scope target.
- Do not attack the host system or other lab machines.
- Find `/home/<user>/user.txt` and `/root/root.txt`.

More provisioning details are documented in `PROVISIONING.md`.
