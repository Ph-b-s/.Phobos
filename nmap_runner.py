"""Safe, non-shell nmap execution for the first Phobos agent build."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from urllib.parse import urlparse

from scope import ScopeError, ScopeValidator


class NmapError(RuntimeError):
    """Raised when nmap cannot be executed safely."""


@dataclass(frozen=True, slots=True)
class NmapResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


def target_host(target: str) -> str:
    candidate = target if "://" in target else f"https://{target}"
    parsed = urlparse(candidate)
    if parsed.username or parsed.password or not parsed.hostname:
        raise NmapError("target must be a hostname or IP address")
    if parsed.port is not None:
        raise NmapError("ports are not accepted in the target; Phobos controls scan scope")
    return parsed.hostname


def run_top_ports_scan(
    target: str,
    scope: ScopeValidator,
    *,
    timeout: float = 60.0,
) -> NmapResult:
    if timeout <= 0:
        raise NmapError("nmap timeout must be positive")

    host = target_host(target)
    scope_url = f"https://{host}"
    try:
        scope.validate(scope_url)
    except ScopeError as exc:
        raise NmapError(str(exc)) from exc

    binary = shutil.which("nmap")
    if not binary:
        raise NmapError("nmap was not found in PATH; install nmap on Kali Linux first")

    command = (
        binary,
        "-sT",
        "--top-ports",
        "100",
        "--open",
        "--reason",
        "--",
        host,
    )
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapError(f"nmap timed out after {timeout:g} seconds") from exc
    except OSError as exc:
        raise NmapError(f"could not execute nmap: {exc}") from exc

    return NmapResult(command=command, returncode=completed.returncode, stdout=completed.stdout, stderr=completed.stderr)
