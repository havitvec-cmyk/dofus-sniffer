"""Helpers for discovering the TCP ports used by running Dofus clients."""
from __future__ import annotations

import platform
import socket
import subprocess
from typing import Iterable, List, Optional, Sequence, Tuple

from Misc import sprint, wprint

DEFAULT_PORTS: Sequence[int] = (5555, 443)


def _normalize_port_value(port: object) -> int:
    try:
        value = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid TCP port: {port}") from exc
    if not 0 < value < 65536:
        raise ValueError(f"Port out of range: {value}")
    return value


def normalize_ports(ports: Optional[Iterable[object]]) -> Optional[List[int]]:
    """Normalize a single port or an iterable of ports."""
    if ports is None:
        return None
    if isinstance(ports, (str, int)):
        ports = [ports]
    normalized = [_normalize_port_value(port) for port in ports]
    # Preserve order while removing duplicates.
    seen = []
    for port in normalized:
        if port not in seen:
            seen.append(port)
    return seen


def _discover_with_psutil():
    try:
        import psutil  # type: ignore
    except ImportError:
        return [], []

    ports: set[int] = set()
    interfaces: set[str] = set()
    try:
        addr_map: dict[str, set[str]] = {}
        for iface, addr_info_list in psutil.net_if_addrs().items():
            for addr in addr_info_list:
                if addr.family in (socket.AF_INET, socket.AF_INET6):
                    addr_map.setdefault(addr.address, set()).add(iface)
        for proc in psutil.process_iter(["name", "cmdline"]):
            info = proc.info
            name = (info.get("name") or "").lower()
            cmdline = " ".join(info.get("cmdline") or ()).lower()
            if "dofus" not in name and "dofus" not in cmdline:
                continue
            for conn in proc.connections(kind="inet"):
                if getattr(psutil, "CONN_LISTEN", None) and conn.status == psutil.CONN_LISTEN:
                    continue
                if conn.laddr:
                    local_ip = getattr(conn.laddr, "ip", None) or conn.laddr[0]
                    ports.add(conn.laddr.port)
                    interfaces.update(addr_map.get(local_ip, set()))
                    if (local_ip or "").startswith("127."):
                        interfaces.add("lo")
                if conn.raddr:
                    remote_ip = getattr(conn.raddr, "ip", None) or conn.raddr[0]
                    if (remote_ip or "").startswith("127."):
                        ports.add(conn.raddr.port)
                        interfaces.add("lo")
    except (psutil.Error, OSError) as exc:  # pragma: no cover - defensive
        wprint(f"Failed to inspect Dofus process sockets via psutil: {exc}")
        return [], []

    return sorted(ports), sorted(interfaces)


def _parse_endpoint(endpoint: str) -> Tuple[str, Optional[int]]:
    endpoint = endpoint.strip()
    if not endpoint:
        return "", None
    if endpoint.startswith("[") and "]" in endpoint:
        host, _, rest = endpoint[1:].partition("]")
        _, _, port = rest.partition(":")
    else:
        host, _, port = endpoint.rpartition(":")
    host = host.strip()
    port = port.strip()
    if not port.isdigit():
        return host, None
    return host, int(port)


def _discover_with_ss() -> Tuple[List[int], List[str]]:
    try:
        output = subprocess.check_output(["ss", "-tupn"], text=True, stderr=subprocess.STDOUT)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        wprint(f"Unable to run 'ss' for port discovery: {exc}")
        return [], []

    ports: set[int] = set()
    interfaces: set[str] = set()
    for line in output.splitlines():
        lower = line.lower()
        if "dofus" not in lower:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local_host, local_port = _parse_endpoint(parts[3])
        if local_port:
            ports.add(local_port)
            if (local_host or "").startswith("127."):
                interfaces.add("lo")
        if len(parts) >= 5:
            remote_host, remote_port = _parse_endpoint(parts[4])
            if remote_port and (remote_host or "").startswith("127."):
                ports.add(remote_port)
                interfaces.add("lo")

    return sorted(ports), sorted(interfaces)


def discover_ports_and_interfaces() -> Tuple[List[int], List[str]]:
    ports, interfaces = _discover_with_psutil()
    if ports:
        return ports, interfaces
    return _discover_with_ss()


def default_interfaces() -> List[str]:
    if platform.system() == "Linux":
        return ["any"]
    return []


def resolve_ports_and_interfaces(ports: Optional[Iterable[object]]):
    normalized = normalize_ports(ports)
    if normalized is not None:
        return normalized, default_interfaces()

    detected_ports, detected_ifaces = discover_ports_and_interfaces()
    if detected_ports:
        sprint(
            "Automatically detected Dofus ports: "
            + ", ".join(map(str, detected_ports))
        )
        if detected_ifaces:
            sprint(
                "Automatically selected interfaces: "
                + ", ".join(detected_ifaces)
            )
        interfaces = detected_ifaces or default_interfaces()
        return detected_ports, interfaces

    wprint(
        "Could not automatically determine Dofus ports. Falling back to defaults (5555, 443)."
    )
    return list(DEFAULT_PORTS), default_interfaces()
