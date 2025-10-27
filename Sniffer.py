from scapy.all import sniff, Raw, IP, ICMP # pylint: disable=no-name-in-module
from colorama import Fore, Back, Style
from CustomDataWrapper import Data, Buffer
from ProtocolBuilder import ProtocolBuilder
from Misc import * # pylint: disable=unused-wildcard-import
from dofus_network import resolve_ports_and_interfaces

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

class Sniffer:
    def __init__(self, concatMode = True, ports = None):
        self.protocolBuilder = ProtocolBuilder()
        self.protocol = self.protocolBuilder.protocol
        self.buffer = Buffer()
        self.concatMode = concatMode
        self.lastPkt = None
        self.ports, self.interfaces = resolve_ports_and_interfaces(ports)

    def _build_filter(self):
        if not self.ports:
            return 'tcp'
        port_filters = ' or '.join(f'port {port}' for port in self.ports)
        return f'tcp and ({port_filters})'

    def _get_iface(self):
        if not self.interfaces:
            return None
        if len(self.interfaces) == 1:
            return self.interfaces[0]
        return self.interfaces

    def run(self, callback, whitelist = None, ports = None):
        self.callback = callback
        self.whitelist = whitelist
        if ports is not None:
            self.ports, self.interfaces = resolve_ports_and_interfaces(ports)
        sprint(f"Listening for TCP traffic on ports: {', '.join(map(str, self.ports))}")
        iface = self._get_iface()
        if iface:
            selected = self.interfaces if isinstance(iface, list) else [iface]
            sprint(f"Capturing on interfaces: {', '.join(selected)}")
        sniff(
            filter=self._build_filter(),
            lfilter = lambda pkt: pkt.haslayer(Raw),
            prn = lambda pkt: self.receive(pkt),
            iface=iface,
            store=False
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