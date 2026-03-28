from dataclasses import dataclass
import os
import re
import shlex

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
        r"^printf %s (?:'[A-Za-z0-9+/=]+'|[A-Za-z0-9+/=]+) \| docker exec -i [a-zA-Z0-9_.-]+ (?:wg|awg) pubkey$",
        r"^docker exec [a-zA-Z0-9_.-]+ (?:wg|awg) set [a-zA-Z0-9_.-]+ peer [A-Za-z0-9+/=]+ allowed-ips [0-9.]+/32$",
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
        known_hosts = os.path.expanduser("~/.ssh/known_hosts")
        if os.path.exists(known_hosts):
            client.load_host_keys(known_hosts)
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
