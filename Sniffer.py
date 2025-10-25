import re
import subprocess

from scapy.all import sniff, Raw, IP, ICMP  # pylint: disable=no-name-in-module
from colorama import Fore, Back, Style

from CustomDataWrapper import Data, Buffer
from ProtocolBuilder import ProtocolBuilder
from Misc import *  # pylint: disable=unused-wildcard-import

class Msg():
    def __init__(self, buffer, protocol):
        self.b = True
        self.protocol = protocol
        self.error = ''
        try:
            header = int.from_bytes(buffer.read(2), byteorder="big")
            self.id = header >> 2
            self.lenType = header & 3
            self.dataLen = int.from_bytes(buffer.read(self.lenType), byteorder="big")
            self.checkHeader()
            self.data = Data(buffer.read(self.dataLen))
        except IndexError:
            buffer.pos = 0
            self.b = False
        except ValueError:
            # eprint(self.error)
            buffer.pos = 0
            self.b = False
        else:
            buffer.end()

    def checkHeader(self):
        if not next((item for item in self.protocol['messages'] if item['protocolID'] == self.id), None):
            self.error = 'Could not find message with id: "' + str(self.id) + '"'
            raise ValueError
        elif not self.lenType in [0, 1, 2, 3]:
            self.error = 'Wrong lenType "' + str(self.lenType) + '"'
            raise ValueError

    def __bool__(self):
        return self.b

def _normalize_ports(ports):
    if ports is None:
        return None
    if isinstance(ports, (int, str)):
        ports = [ports]
    normalized = []
    for port in ports:
        try:
            normalized_port = int(port)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid TCP port: {port}") from exc
        if not 0 < normalized_port < 65536:
            raise ValueError(f"Port out of range: {normalized_port}")
        normalized.append(normalized_port)
    # Preserve order while removing duplicates
    return list(dict.fromkeys(normalized))


def _auto_detect_dofus_ports():
    ports = set()

    try:
        import psutil  # type: ignore
    except ImportError:
        psutil = None

    if psutil:
        try:
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
                        ports.add(conn.laddr.port)
                    if conn.raddr:
                        ports.add(conn.raddr.port)
        except Exception as exc:  # pragma: no cover - defensive
            wprint(f"Failed to inspect Dofus process sockets via psutil: {exc}")

    if ports:
        return sorted(ports)

    try:
        output = subprocess.check_output(["ss", "-tupn"], text=True, stderr=subprocess.STDOUT)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        wprint(f"Unable to run 'ss' for port discovery: {exc}")
        return []

    for line in output.splitlines():
        if "dofus" not in line.lower():
            continue
        for match in re.findall(r":(\d+)", line):
            port = int(match)
            if 0 < port < 65536:
                ports.add(port)

    return sorted(ports)


class Sniffer:
    def __init__(self, concatMode = True, ports = None):
        self.protocolBuilder = ProtocolBuilder()
        self.protocol = self.protocolBuilder.protocol
        self.buffer = Buffer()
        self.concatMode = concatMode
        self.lastPkt = None
        normalized = _normalize_ports(ports)
        if normalized is not None:
            self.ports = normalized
        else:
            detected = _auto_detect_dofus_ports()
            if detected:
                sprint(f"Automatically detected Dofus ports: {', '.join(map(str, detected))}")
                self.ports = detected
            else:
                wprint("Could not automatically determine Dofus ports. Falling back to defaults (5555, 443).")
                self.ports = [5555, 443]

    def _build_filter(self):
        if not self.ports:
            return 'tcp'
        port_filters = ' or '.join(f'port {port}' for port in self.ports)
        return f'tcp and ({port_filters})'

    def run(self, callback, whitelist = None, ports = None):
        self.callback = callback
        self.whitelist = whitelist
        override_ports = _normalize_ports(ports)
        if override_ports is not None:
            self.ports = override_ports
        sprint(f"Listening for TCP traffic on ports: {', '.join(map(str, self.ports))}")
        sniff(
            filter=self._build_filter(),
            lfilter = lambda pkt: pkt.haslayer(Raw),
            prn = lambda pkt: self.receive(pkt)
        )

    def receive(self, pkt):
        if self.lastPkt and pkt.getlayer(IP).src != self.lastPkt.getlayer(IP).src:
            self.lastPkt = None
        if self.lastPkt and pkt.getlayer(IP).id < self.lastPkt.getlayer(IP).id:
            self.buffer.reorder(bytes(pkt.getlayer(Raw)),
            len(self.lastPkt.getlayer(Raw)))
        else:
            if self.concatMode:
                self.buffer += bytes(pkt.getlayer(Raw))
            else:
                self.buffer = Buffer()
                self.buffer += bytes(pkt.getlayer(Raw))
        self.lastPkt = pkt
        msg = Msg(self.buffer, self.protocol)
        while msg:
            # print('ID: ' + str(msg.id) + ' - dataLen: ' + str(len(msg.data)))
            if self.whitelist:
                if msg.id in self.whitelist:
                    self.callback(msg.id, self.protocolBuilder.build(msg.id, msg.data))
            else:
                self.callback(msg.id, self.protocolBuilder.build(msg.id, msg.data))
            msg = Msg(self.buffer, self.protocol)
