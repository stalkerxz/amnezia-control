from dataclasses import dataclass
import os
import shlex
import paramiko


@dataclass
class ExecutionResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str


class SafeSSHExecutor:
    ALLOWLIST = {
        "awg": ["show", "genkey", "pubkey"],
        "systemctl": ["status", "restart", "is-active", "amnezia-awg"],
        "cat": ["/etc/amnezia"],
        "ls": ["/etc/amnezia"],
    }

    def __init__(self, host: str, username: str, port: int = 22, key_path: str | None = None, timeout: int = 10):
        self.host = host
        self.username = username
        self.port = port
        self.key_path = key_path
        self.timeout = timeout

    def _validate(self, command: str):
        parts = shlex.split(command)
        if not parts:
            raise ValueError("Empty command")
        base = parts[0]
        if base not in self.ALLOWLIST:
            raise ValueError("Command not allowed")
        allowed_args = self.ALLOWLIST[base]
        for arg in parts[1:]:
            if arg in allowed_args:
                continue
            if any(arg.startswith(prefix) for prefix in allowed_args if prefix.startswith("/")):
                continue
            raise ValueError(f"Argument not allowed: {arg}")

    @staticmethod
    def _host_key_policy() -> paramiko.MissingHostKeyPolicy:
        if os.getenv("SSH_ALLOW_UNKNOWN_HOSTS", "0") == "1":
            # Development-only override. Keep strict checking in production.
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
