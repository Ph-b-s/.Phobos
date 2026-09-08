"""Bounded Nmap discovery used to enrich the Phobos attack-surface graph."""
from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import urlparse

from scope import ScopeError, ScopeValidator


class NmapError(RuntimeError):
    """Raised when Nmap cannot be prepared, parsed, or executed safely."""


@dataclass(frozen=True, slots=True)
class OpenPort:
    """One TCP service reported by Nmap."""

    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    reason: str = ""


@dataclass(frozen=True, slots=True)
class NmapResult:
    """Raw Nmap output plus normalized service observations."""

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    ports: tuple[OpenPort, ...] = ()


def target_host(target: str) -> str:
    """Extract only the host from an HTTP(S) target; URL paths are irrelevant to Nmap."""
    candidate = target.strip() if "://" in target else f"https://{target.strip()}"
    parsed = urlparse(candidate)
    if parsed.username or parsed.password or not parsed.hostname:
        raise NmapError("target must be a hostname or IP address")
    if parsed.port is not None:
        raise NmapError("explicit ports are not accepted; Phobos controls network-scan scope")
    return parsed.hostname.rstrip(".").lower()


def prepare_top_ports_scan(
    target: str,
    scope: ScopeValidator,
    *,
    require_nmap: bool = True,
) -> tuple[str, ...]:
    """Validate the target and return a fixed, non-shell Nmap command."""
    host = target_host(target)
    try:
        scope.validate(f"https://{host}")
    except ScopeError as exc:
        raise NmapError(str(exc)) from exc

    binary = shutil.which("nmap") if require_nmap else "nmap"
    if not binary:
        raise NmapError("nmap was not found in PATH; install nmap on Kali Linux first")

    return (
        binary,
        "-sT",
        "--top-ports",
        "100",
        "--open",
        "--reason",
        "-oX",
        "-",
        "--",
        host,
    )


def parse_nmap_xml(xml_text: str) -> tuple[OpenPort, ...]:
    """Normalize Nmap XML without accepting arbitrary command output as findings."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapError("nmap returned invalid XML output") from exc

    ports: list[OpenPort] = []
    for port in root.findall(".//port"):
        protocol = port.attrib.get("protocol", "").lower()
        try:
            number = int(port.attrib["portid"])
        except (KeyError, ValueError) as exc:
            raise NmapError("nmap returned a port with an invalid port number") from exc
        state = port.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        service = port.find("service")
        attrs = service.attrib if service is not None else {}
        ports.append(
            OpenPort(
                port=number,
                protocol=protocol,
                state="open",
                service=attrs.get("name", ""),
                product=attrs.get("product", ""),
                version=attrs.get("version", ""),
                reason=state.attrib.get("reason", ""),
            )
        )
    return tuple(sorted(ports, key=lambda item: (item.port, item.protocol)))


def run_top_ports_scan(
    target: str,
    scope: ScopeValidator,
    *,
    timeout: float = 60.0,
    execute: bool = True,
) -> NmapResult:
    """Run a bounded top-100 TCP discovery scan and return normalized open ports."""
    if timeout <= 0:
        raise NmapError("nmap timeout must be positive")

    command = prepare_top_ports_scan(target, scope, require_nmap=execute)
    if not execute:
        return NmapResult(command=command, returncode=0, stdout="", stderr="")

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

    ports = parse_nmap_xml(completed.stdout) if completed.stdout.strip() else ()
    return NmapResult(
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        ports=ports,
    )
