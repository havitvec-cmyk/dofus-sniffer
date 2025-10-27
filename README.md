# Dofus Sniffer
**This project is still in progress**  
I will add complete instructions soon

### Built With

* [Python 3.7](https://www.python.org/downloads/)
* [Scapy 2.4.4](https://scapy.readthedocs.io/en/latest/installation.html)

## Protocol Builder

```
{
    "channel": 5,
    "content": "iop 200 cherche guilde alliance thor svp",
    "timestamp": 1605226795,
    "fingerprint": "5o29ym1r",
    "senderId": 45476937933.0,
    "senderName": "Babylon",
    "prefix": "",
    "senderAccountId": 50733921,
}
```

```
{
    "objectType": 16,
    "itemTypeDescriptions": [
        {
            "objectUID": 219063794,
            "objectGID": 7227,
            "objectType": 16,
            "effects": [
                {"actionId": 125, "value": 144},
                {"actionId": 118, "value": 40},
                {"actionId": 124, "value": 25},
                {"actionId": 213, "value": 3},
                {"actionId": 212, "value": 3},
                {"actionId": 117, "value": 1},
            ],
            "prices": [180000, 0, 0],
        },
        ...
    ]
}
```

## Sniffer configuration

The sniffer attempts to locate running Dofus clients and monitors the TCP ports
those processes use. In most environments you can run `main.py` directly and the
sniffer will discover the correct ports and interfaces automatically. When
auto-detection fails the sniffer falls back to ports 5555 and 443.

You can still override the ports when instantiating the sniffer:

```python
from Sniffer import Sniffer

Sniffer(ports=5556).run(callback)
# or multiple ports
Sniffer(ports=[5555, 5556]).run(callback)
```

The override is also available on `run`:

```python
sniffer = Sniffer()
sniffer.run(callback, ports=443)
```

### Debug: always see packets
# Loopback (IPC)
sudo python tools/scapy_lo_test.py

# Multi-if, robust capture that always prints:
sudo python tools/live_capture_debug.py -i lo,wlan0 -p 26117,52000-60000

# Main sniffer with robust mode:
sudo python main.py --loose-bpf --print-raw --interfaces lo,wlan0 --ports 26117,52000-60000

Notes

Replace wlan0 with your actual Wi-Fi interface (e.g., wlp3s0).

Refresh ports from sudo ss -tupn | grep -i dofus each launch if needed.
