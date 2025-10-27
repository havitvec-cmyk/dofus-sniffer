# tools/live_capture_debug.py
import argparse
from typing import List, Set

from scapy.all import sniff, conf
from scapy.layers.inet import TCP

def parse_ports(s: str) -> Set[int]:
    st = set()
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

def main():
    ap = argparse.ArgumentParser(description="Minimal debug capture that ALWAYS prints something.")
    ap.add_argument("--interfaces", "-i", default="lo",
                    help="Comma-separated list, e.g. 'lo,wlan0' or 'lo,wlp3s0'")
    ap.add_argument("--ports", "-p", default="26117",
                    help="Comma/Range, e.g. '26117,52038-52060'")
    ap.add_argument("--promisc", action="store_true", help="Enable promisc (not needed for lo)")
    args = ap.parse_args()

    ifaces: List[str] = [x.strip() for x in args.interfaces.split(",") if x.strip()]
    PORTS: Set[int] = parse_ports(args.ports)

    # Scapy capture tuning for loopback/BPF reliability
    conf.use_pcap = True
    conf.sniff_promisc = bool(args.promisc)

    def lfilter(pkt) -> bool:
        try:
            tcp = pkt[TCP]
            return tcp.sport in PORTS or tcp.dport in PORTS
        except Exception:
            return False

    def show(pkt):
        try:
            ip = pkt.getlayer("IP")
            tcp = pkt.getlayer("TCP")
            if ip and tcp:
                print(f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}  len={len(bytes(pkt))}")
            else:
                print(pkt.summary())
        except Exception:
            print(pkt.summary())

    # Loose BPF = "tcp"; narrowing happens in lfilter so we don't miss anything
    sniff(iface=ifaces, filter="tcp", lfilter=lfilter, prn=show, store=False)

if __name__ == "__main__":
    main()
