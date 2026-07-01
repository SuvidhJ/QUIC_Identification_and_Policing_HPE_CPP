from scapy.all import sniff
from scapy.layers.inet import IP

from app import socketio


def process(pkt):

    if IP not in pkt:
        return

    socketio.emit(
        "packet",
        {
            "time": pkt.time,
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "proto": pkt[IP].proto,
            "length": len(pkt)
        }
    )


sniff(
    iface="hc-eth0",
    prn=process,
    store=False
)
