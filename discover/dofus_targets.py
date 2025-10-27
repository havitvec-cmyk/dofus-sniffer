# discover/dofus_targets.py
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Set, Tuple, Optional, List

@dataclass
class TargetSet:
    ports: Set[int] = field(default_factory=set)
    ips: Set[str] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def update(self, ports: Set[int], ips: Set[str]):
        with self.lock:
            self.ports = set(ports)
            self.ips = set(ips)

    def snapshot(self) -> Tuple[Set[int], Set[str]]:
        with self.lock:
            return set(self.ports), set(self.ips)

DEFAULT_NAMES = ["dofus", "dofus1electron", "ankama", "retro", "electron"]

def _run_ss() -> str:
    try:
        out = subprocess.check_output(["ss", "-tunp"], stderr=subprocess.DEVNULL)
        return out.decode("utf-8", errors="replace")
    except Exception:
        return ""

def _match_line(line: str, names: List[str]) -> bool:
    l = line.lower()
    return any(n in l for n in names)

def _parse_line(line: str) -> Optional[Tuple[str,int,str,int]]:
    parts = line.split()
    cand = [p for p in parts if ":" in p]
    if len(cand) < 2:
        return None
    try:
        laddr = cand[0].rsplit(":", 1)
        raddr = cand[1].rsplit(":", 1)
        lip, lport = laddr[0], int(laddr[1])
        rip, rport = raddr[0], int(raddr[1])
        return lip, lport, rip, rport
    except Exception:
        return None

def discover_targets(targets: TargetSet,
                     proc_names: Optional[List[str]] = None,
                     interval_s: float = 3.0):
    names = proc_names or DEFAULT_NAMES
    while True:
        text = _run_ss()
        ports: Set[int] = set()
        ips: Set[str] = set()
        for line in text.splitlines():
            if not _match_line(line, names):
                continue
            parsed = _parse_line(line)
            if not parsed:
                continue
            lip, lport, rip, rport = parsed
            ports.add(lport)
            ports.add(rport)
            if lip not in ("*", "0.0.0.0"):
                ips.add(lip)
            if rip not in ("*", "0.0.0.0"):
                ips.add(rip)
        ports.add(26117)
        targets.update(ports, ips)
        time.sleep(interval_s)

def start_discovery_thread(targets: TargetSet,
                           proc_names: Optional[List[str]],
                           interval_s: float) -> threading.Thread:
    t = threading.Thread(target=discover_targets,
                         args=(targets, proc_names, interval_s),
                         daemon=True)
    t.start()
    return t
