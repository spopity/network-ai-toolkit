"""Persistent SSH shell to the router with hard per-command limits."""
import socket
import threading
import time
from dataclasses import dataclass

import paramiko


@dataclass
class CommandResult:
    command: str
    output: str
    exit_code: int | None
    duration_ms: int
    timed_out: bool = False
    truncated: bool = False
    error: str | None = None


class RouterShell:
    def __init__(self, host: str, port: int = 22, username: str = None, key_filename: str = None,
                 connect_timeout: int = 10, max_output_bytes: int = 256_000):
        self.host = host
        self.port = port
        self.username = username
        self.key_filename = key_filename
        self.connect_timeout = connect_timeout
        self.max_output_bytes = max_output_bytes
        self._client = None
        self._lock = threading.Lock()

    def _connect(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.host, port=self.port, username=self.username, key_filename=self.key_filename,
                       timeout=self.connect_timeout, banner_timeout=self.connect_timeout,
                       auth_timeout=self.connect_timeout, look_for_keys=False, allow_agent=False)
        client.get_transport().set_keepalive(30)
        self._client = client

    def _alive(self) -> bool:
        t = self._client.get_transport() if self._client else None
        return bool(t and t.is_active())

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def run(self, command: str, timeout: int = 30) -> CommandResult:
        with self._lock:
            start = time.monotonic()
            try:
                if not self._alive():
                    self.close()
                    self._connect()
                return self._exec(command, timeout, start)
            except (paramiko.SSHException, socket.error, EOFError) as e:
                # one reconnect attempt for a stale connection
                self.close()
                try:
                    self._connect()
                    return self._exec(command, timeout, time.monotonic())
                except Exception as e2:
                    self.close()
                    return CommandResult(command, "", None, int((time.monotonic() - start) * 1000),
                                         error=f"SSH failure: {e2 or e}")

    def _exec(self, command: str, timeout: int, start: float) -> CommandResult:
        chan = self._client.get_transport().open_session()
        # a pty makes the router kill the process (SIGHUP) when we close the
        # channel on timeout; it also merges stderr into stdout, which is fine here
        chan.get_pty(width=200)
        chan.settimeout(1.0)
        chan.exec_command(command)
        buf = bytearray()
        timed_out = truncated = False
        deadline = start + timeout
        try:
            while True:
                if chan.recv_ready():
                    data = chan.recv(65536)
                    if data:
                        buf.extend(data)
                        if len(buf) > self.max_output_bytes:
                            truncated = True
                            break
                        continue
                if chan.exit_status_ready() and not chan.recv_ready():
                    break
                if time.monotonic() > deadline:
                    timed_out = True
                    break
                time.sleep(0.05)
            exit_code = chan.recv_exit_status() if chan.exit_status_ready() else None
        finally:
            chan.close()
        out = buf[: self.max_output_bytes].decode(errors="replace").replace("\r\n", "\n")
        return CommandResult(command, out, exit_code, int((time.monotonic() - start) * 1000),
                             timed_out=timed_out, truncated=truncated)
