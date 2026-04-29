from dataclasses import dataclass
import os
from pathlib import Path
import re
import shlex
import subprocess

import paramiko


@dataclass
class ExecutionResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str


class SafeSSHExecutor:
    """Allowlisted SSH executor for Amnezia runtime operations."""

    ALLOWED_PATTERNS = [
        r"^docker ps --format '\{\{\.Names\}\}'$",
        r"^docker ps -a --format '\{\{\.Names\}\}'$",
        r"^docker inspect [a-zA-Z0-9_.-]+$",
        r"^docker exec [a-zA-Z0-9_.-]+ (?:wg|awg) show(?: [a-zA-Z0-9_.-]+)?(?: dump| interfaces| public-key)?$",
        r"^docker exec [a-zA-Z0-9_.-]+ (?:wg|awg) genkey$",
        r"^docker exec [a-zA-Z0-9_.-]+ (?:wg|awg) genpsk$",
        r"^printf %s (?:'[A-Za-z0-9+/=]+'|[A-Za-z0-9+/=]+) \| docker exec -i [a-zA-Z0-9_.-]+ (?:wg|awg) pubkey$",
        r"^docker exec [a-zA-Z0-9_.-]+ (?:wg|awg) set [a-zA-Z0-9_.-]+ peer [A-Za-z0-9+/=]+ allowed-ips [0-9.]+/32$",
        r"^printf %s (?:'[A-Za-z0-9+/=]+'|[A-Za-z0-9+/=]+) \| docker exec -i [a-zA-Z0-9_.-]+ (?:wg|awg) set [a-zA-Z0-9_.-]+ peer [A-Za-z0-9+/=]+ preshared-key /dev/stdin allowed-ips [0-9.]+/32$",
        r"^docker exec [a-zA-Z0-9_.-]+ (?:wg|awg) set [a-zA-Z0-9_.-]+ peer [A-Za-z0-9+/=]+ remove$",
        r"^docker exec [a-zA-Z0-9_.-]+ ls (?:/etc/amnezia|/opt/amnezia|/etc/wireguard)$",
        r"^docker exec [a-zA-Z0-9_.-]+ cat (?:/etc/amnezia/[a-zA-Z0-9_./-]+|/etc/wireguard/[a-zA-Z0-9_./-]+|/opt/amnezia/[a-zA-Z0-9_./-]+)$",
    ]

    def __init__(self, host: str, username: str, port: int = 22, key_path: str | None = None, timeout: int = 15):
        self.host = host
        self.username = username
        self.port = port
        self.key_path = key_path
        self.timeout = timeout

    def _validate(self, command: str):
        shlex.split(command)
        if not any(re.fullmatch(pattern, command) for pattern in self.ALLOWED_PATTERNS):
            raise ValueError("Command not allowed")

    @staticmethod
    def _host_key_policy() -> paramiko.MissingHostKeyPolicy:
        if os.getenv("SSH_ALLOW_UNKNOWN_HOSTS", "0") == "1":
            return paramiko.WarningPolicy()
        return paramiko.RejectPolicy()

    def run(self, command: str) -> ExecutionResult:
        self._validate(command)
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        known_hosts = self.ensure_known_host(self.host, self.port)
        client.load_host_keys(str(known_hosts))
        client.set_missing_host_key_policy(self._host_key_policy())

        connect_kwargs = {
            "hostname": self.host,
            "username": self.username,
            "port": self.port,
            "timeout": self.timeout,
            "allow_agent": True,
            "look_for_keys": True,
        }
        if self.key_path:
            connect_kwargs["key_filename"] = self.key_path
        elif os.getenv("SSH_PASSWORD"):
            connect_kwargs["password"] = os.getenv("SSH_PASSWORD")

        client.connect(**connect_kwargs)
        try:
            _, stdout, stderr = client.exec_command(command, timeout=self.timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            exit_code = stdout.channel.recv_exit_status()
        finally:
            client.close()
        return ExecutionResult(command=command, exit_code=exit_code, stdout=out, stderr=err)
    @staticmethod
    def _known_hosts_path() -> Path:
        return Path(os.getenv("SSH_KNOWN_HOSTS_PATH", "/tmp/amnezia-control/known_hosts"))

    @classmethod
    def ensure_known_host(cls, host: str, port: int) -> Path:
        known_hosts_path = cls._known_hosts_path()
        known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
        if not known_hosts_path.exists():
            known_hosts_path.touch(mode=0o600)
        else:
            known_hosts_path.chmod(0o600)

        host_token = f"[{host}]:{port}" if port != 22 else host
        existing_lines = []
        if known_hosts_path.exists():
            existing_lines = known_hosts_path.read_text(encoding="utf-8").splitlines()

        keyscan_result = subprocess.run(
            ["ssh-keyscan", "-p", str(port), host],
            capture_output=True,
            text=True,
            check=False,
        )
        if keyscan_result.returncode != 0 or not keyscan_result.stdout.strip():
            stderr = (keyscan_result.stderr or "").strip()
            details = f": {stderr}" if stderr else ""
            raise RuntimeError(f"Failed to fetch SSH host key for {host}:{port}{details}")

        scanned_lines = [line.strip() for line in keyscan_result.stdout.splitlines() if line.strip() and not line.startswith("#")]
        if not scanned_lines:
            raise RuntimeError(f"Failed to parse SSH host key for {host}:{port}")

        existing_for_host = [line.strip() for line in existing_lines if line.strip().startswith(f"{host_token} ")]
        if existing_for_host:
            if any(line not in existing_for_host for line in scanned_lines):
                raise RuntimeError(f"SSH host key mismatch for {host}:{port}")
            return known_hosts_path

        with known_hosts_path.open("a", encoding="utf-8") as fh:
            for clean in scanned_lines:
                fh.write(f"{clean}\n")
        return known_hosts_path
