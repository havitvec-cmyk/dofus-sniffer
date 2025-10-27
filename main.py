import argparse
from typing import Iterable, Optional, Set, List

from scapy.all import conf, sniff
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from Misc import sprint
from Sniffer import Sniffer
from parser.dofus_retro_framing import RetroReassembler
from discover.dofus_targets import TargetSet, start_discovery_thread
from protocol.retro_handlers import dispatch as retro_dispatch

conf.use_pcap = True
conf.sniff_promisc = False


RETRO = RetroReassembler()
TARGETS = TargetSet()


def _parse_ports(s: str) -> Set[int]:
    st: Set[int] = set()
    for part in s.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = map(int, part.split('-', 1))
            st.update(range(min(a, b), max(a, b) + 1))
        else:
            st.add(int(part))
    return st


def _raw_fallback_print(pkt):
    try:
        ip = pkt.getlayer("IP")
        tcp = pkt.getlayer("TCP")
        if ip and tcp:
            print(f"[RAW] {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}  len={len(bytes(pkt))}")
        else:
            print("[RAW]", pkt.summary())
    except Exception:
        try:
            print("[RAW]", pkt.summary())
        except Exception:
            pass


def action(id, msg):
    print(msg)
    print('-')


def main(callback=action, ports: Optional[Iterable[int]] = None):
    Sniffer(ports=ports).run(callback)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Dofus packet sniffer")
    parser.add_argument("--loose-bpf", action="store_true",
                        help="Use filter='tcp' + Python lfilter based on ports (recommended).")
    parser.add_argument("--print-raw", action="store_true",
                        help="Always print a raw summary alongside decoded messages.")
    parser.add_argument("--interfaces", default=None,
                        help="Comma-separated list to override autodetected interfaces.")
    parser.add_argument("--ports", default=None,
                        help="Comma-separated or ranges to override autodetected ports.")
    parser.add_argument("--retro", action="store_true",
                        help="Use Dofus Retro ASCII parser.")
    parser.add_argument("--only-dofus", action="store_true",
                        help="Capture only Dofus process sockets.")
    parser.add_argument("--proc-name", action="append",
                        help="Process name(s) to match, e.g. dofus1electron.")
    parser.add_argument("--refresh-seconds", type=float, default=3.0,
                        help="Refresh rate for Dofus socket discovery.")
    return parser


def _run_cli():
    args = _build_parser().parse_args()

    if not hasattr(args, "retro"):
        args.retro = True
    elif not args.retro:
        args.retro = True

    if args.only_dofus:
        names = args.proc_name or None
        start_discovery_thread(TARGETS, names, args.refresh_seconds)

    manual_ports_list: Optional[List[int]] = None
    manual_ports_set: Set[int] = set()
    if args.ports:
        manual_ports_set = _parse_ports(args.ports)
        manual_ports_list = sorted(manual_ports_set)

    sniffer = Sniffer(ports=manual_ports_list)

    if args.interfaces:
        interfaces = [x.strip() for x in args.interfaces.split(',') if x.strip()]
        if interfaces:
            sniffer.interfaces = interfaces
    interfaces = sniffer.interfaces or []
    iface_param: Optional[object]
    if not interfaces:
        iface_param = None
    elif len(interfaces) == 1:
        iface_param = interfaces[0]
    else:
        iface_param = interfaces

    ports_list = sniffer.ports or []
    if manual_ports_list is not None:
        ports_list = manual_ports_list
        sniffer.ports = ports_list
    ports_set = manual_ports_set or set(ports_list)

    if ports_list:
        sprint(f"Listening for TCP traffic on ports: {', '.join(map(str, ports_list))}")
    if interfaces:
        selected = interfaces if isinstance(interfaces, list) else list(interfaces)
        sprint(f"Capturing on interfaces: {', '.join(selected)}")

    def decoded_callback(message_id, message):
        sniffer._decoded_last = True
        print(message)
        print('-')
        if args.print_raw:
            try:
                _raw_fallback_print(sniffer._current_packet)
            except Exception:
                pass

    sniffer.callback = decoded_callback
    sniffer.whitelist = None

    def on_packet(pkt):
        sniffer._current_packet = pkt
        if args.retro:
            frames_emitted = False
            try:
                if IP in pkt and TCP in pkt:
                    ip = pkt[IP]
                    tcp = pkt[TCP]
                    raw = pkt.getlayer(Raw)
                    if raw and getattr(raw, "load", None):
                        k = (ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
                        frames = RETRO.feed(k, raw.load)
                        for fr in frames:
                            opcode = fr["opcode"]
                            text = fr["text"]
                            summary = retro_dispatch(opcode, text)
                            print(
                                f"[RETRO] {ip.src}:{tcp.sport}->{ip.dst}:{tcp.dport} "
                                f"op={opcode or '?'} {summary}"
                            )
                            frames_emitted = True
            except Exception as e:
                print("retro_packet_error:", e)

            if args.print_raw or not frames_emitted:
                try:
                    _raw_fallback_print(pkt)
                except Exception:
                    pass
            return

        if not pkt.haslayer(Raw):
            if args.print_raw:
                try:
                    _raw_fallback_print(pkt)
                except Exception:
                    pass
            return

        sniffer._decoded_last = False
        sniffer._current_packet = pkt
        sniffer.receive(pkt)
        # Ensure we see traffic even if parser didn’t match
        try:
            if not getattr(sniffer, "_decoded_last", False):
                _raw_fallback_print(pkt)
        except Exception:
            pass

    def lfilter_only_dofus(pkt) -> bool:
        if not args.only_dofus:
            return True
        if IP not in pkt or TCP not in pkt:
            return False
        ip = pkt[IP]
        tcp = pkt[TCP]
        ports, ips = TARGETS.snapshot()
        try:
            sport = int(tcp.sport)
            dport = int(tcp.dport)
        except Exception:
            sport = tcp.sport
            dport = tcp.dport
        if sport in ports or dport in ports:
            return True
        if ip.src in ips or ip.dst in ips:
            return True
        return False

    if args.loose_bpf:
        bpf = "tcp"

        def _lfilter(pkt):
            if not lfilter_only_dofus(pkt):
                return False
            try:
                tcp = pkt[TCP]
                sport = int(tcp.sport)
                dport = int(tcp.dport)
            except Exception:
                return False

            combined_ports: Set[int]
            if ports_set:
                combined_ports = set(ports_set)
            else:
                combined_ports = set()
            if args.only_dofus:
                dyn_ports, _ = TARGETS.snapshot()
                if dyn_ports:
                    combined_ports.update(dyn_ports)
            if not combined_ports:
                return True
            return (sport in combined_ports) or (dport in combined_ports)

        sniff(iface=iface_param, filter=bpf, lfilter=_lfilter, prn=on_packet, store=False)
    else:
        sniff(
            iface=iface_param,
            filter=sniffer._build_filter(),
            lfilter=lambda pkt: pkt.haslayer(Raw) and lfilter_only_dofus(pkt),
            prn=on_packet,
            store=False,
        )


if __name__ == "__main__":
    _run_cli()
