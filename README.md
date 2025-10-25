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

## Sniffer configuration

When the sniffer starts it automatically looks for running Dofus processes and
derives the active TCP ports from their sockets. This means in most setups you
can simply run `main.py` without any manual configuration and packets will be
captured as soon as the game is connected.

If automatic detection fails, the sniffer falls back to the historical game
ports (5555 and 443) and prints a warning. You can always override the ports
explicitly when instantiating the sniffer:

```python
from Sniffer import Sniffer

Sniffer(ports=5556).run(callback)
# or multiple ports
Sniffer(ports=[5555, 5556]).run(callback)
```

The override also works when calling `run`:

```python
sniffer = Sniffer()
sniffer.run(callback, ports=443)
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
