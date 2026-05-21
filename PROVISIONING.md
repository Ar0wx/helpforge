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

## Final Cleanup Before Export

Run cleanup only after validation and before exporting or submitting the final
VM state:

```bash
./cleanup.sh
```

The cleanup role removes provisioning leftovers and shell history artifacts.
