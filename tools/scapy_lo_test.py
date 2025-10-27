from scapy.all import sniff, conf
from scapy.layers.inet import TCP

conf.use_pcap = True
conf.sniff_promisc = False

def show(p):
    try:
        print(p.summary(), len(bytes(p)))
    except Exception:
        print("err printing packet")

sniff(iface="lo", filter="tcp port 26117", prn=show, store=False)
