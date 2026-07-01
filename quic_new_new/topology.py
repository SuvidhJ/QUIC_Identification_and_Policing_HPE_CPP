#!/usr/bin/env python3
"""
Mininet topology for QUIC QoS demonstration.

Nodes:
  h1  (10.0.0.1)   – PCAP replay host
  h2  (10.0.0.2)   – Destination host
  hc  (10.0.0.99)  – Classifier / dashboard host
  s1               – OVS switch

Links:
  h1 ──── s1  (s1-eth1, 10 Mbps)
  h2 ──── s1  (s1-eth2, 10 Mbps)  ← HTB QoS applied here
  hc ──── s1  (s1-eth3, 10 Mbps)  ← traffic mirror here

QoS queues on s1-eth2 (linux-htb):
  Queue 0  Default  2–10 Mbps   (unclassified flows)
  Queue 1  Video    4– 8 Mbps   ← highest priority
  Queue 2  Data     2– 5 Mbps
  Queue 3  Web      1– 3 Mbps

Flow classification happens on hc; once the ML model assigns a class
to a flow the classifier pushes an OpenFlow enqueue rule via ovs-ofctl
so subsequent packets for that flow are steered to the correct queue.
"""

from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI
import subprocess
import time

# ── QoS constants (keep in sync with ovs_qos.py) ────────────────────────────
EGRESS_PORT = "s1-eth2"
TOTAL_BPS   = 10_000_000   # 10 Mbps

QUEUE_BW = {
    # queue_num: (min_bps, max_bps)
    0: (2_000_000, 10_000_000),   # Default
    1: (4_000_000,  8_000_000),   # Video
    2: (2_000_000,  5_000_000),   # Data
    3: (1_000_000,  3_000_000),   # Web
}


def setup_qos(egress_port: str = EGRESS_PORT) -> None:
    """
    Configure HTB QoS on the egress port toward h2.

    Queue layout:
      0 → Default (unclassified)
      1 → Video   (class 1, highest priority)
      2 → Data    (class 2)
      3 → Web     (class 0)
    """
    print(f"\n[QoS] Removing any existing QoS on {egress_port} …")
    subprocess.run(
        f"ovs-vsctl clear port {egress_port} qos",
        shell=True, check=False
    )
    # Also garbage-collect orphaned QoS / Queue objects from previous runs
    subprocess.run("ovs-vsctl --all destroy qos",   shell=True, check=False)
    subprocess.run("ovs-vsctl --all destroy queue", shell=True, check=False)
    time.sleep(0.5)

    def bps(n): return str(int(n))

    q0_min, q0_max = QUEUE_BW[0]
    q1_min, q1_max = QUEUE_BW[1]
    q2_min, q2_max = QUEUE_BW[2]
    q3_min, q3_max = QUEUE_BW[3]

    cmd = (
        f"ovs-vsctl set port {egress_port} qos=@newqos -- "
        f"--id=@newqos create qos type=linux-htb "
        f"other-config:max-rate={bps(TOTAL_BPS)} "
        f"queues:0=@q0 queues:1=@q1 queues:2=@q2 queues:3=@q3 -- "
        # Queue 0 – Default
        f"--id=@q0 create queue "
        f"other-config:min-rate={bps(q0_min)} "
        f"other-config:max-rate={bps(q0_max)} -- "
        # Queue 1 – Video (highest priority, gets most guaranteed BW)
        f"--id=@q1 create queue "
        f"other-config:min-rate={bps(q1_min)} "
        f"other-config:max-rate={bps(q1_max)} -- "
        # Queue 2 – Data
        f"--id=@q2 create queue "
        f"other-config:min-rate={bps(q2_min)} "
        f"other-config:max-rate={bps(q2_max)} -- "
        # Queue 3 – Web
        f"--id=@q3 create queue "
        f"other-config:min-rate={bps(q3_min)} "
        f"other-config:max-rate={bps(q3_max)}"
    )

    subprocess.run(cmd, shell=True, check=True)

    print(f"[QoS] HTB configured on {egress_port}  (total {TOTAL_BPS//1_000_000} Mbps)")
    print(f"  Queue 0 (Default) : {q0_min//1_000_000}–{q0_max//1_000_000} Mbps")
    print(f"  Queue 1 (Video)   : {q1_min//1_000_000}–{q1_max//1_000_000} Mbps  ← highest priority")
    print(f"  Queue 2 (Data)    : {q2_min//1_000_000}–{q2_max//1_000_000} Mbps")
    print(f"  Queue 3 (Web)     : {q3_min//1_000_000}–{q3_max//1_000_000} Mbps")


def setup_default_of_rules(switch: str = "s1") -> None:
    """
    Install catch-all OpenFlow rule that sends all traffic from h1 (port 1)
    toward h2 (port 2) through queue 0 (Default) at low priority.
    Classified flows will be installed at priority 100 and override this.
    """
    # Delete any stale flows first
    subprocess.run(f"ovs-ofctl del-flows {switch}", shell=True, check=False)

    # Default: ingress on port 1 → enqueue on port 2, queue 0
    subprocess.run(
        f"ovs-ofctl add-flow {switch} "
        f"priority=1,in_port=1,actions=enqueue:2:0",
        shell=True, check=False
    )

    # Also allow h2 → h1 direction without shaping (or enqueue to default)
    subprocess.run(
        f"ovs-ofctl add-flow {switch} "
        f"priority=1,in_port=2,actions=enqueue:1:0",
        shell=True, check=False
    )

    print(f"[OpenFlow] Default enqueue rules installed on {switch}")


def setup_mirror(switch_name: str, classifier_port: str) -> None:
    """Mirror all traffic to the classifier host (hc)."""
    cmd = (
        f"ovs-vsctl -- set Bridge {switch_name} mirrors=@m "
        f"-- --id=@p get Port {classifier_port} "
        f"-- --id=@m create Mirror "
        f"name=classifier-tap "
        f"select-all=true "
        f"output-port=@p"
    )
    subprocess.run(cmd, shell=True, check=True)
    print(f"[Mirror] All traffic mirrored to {classifier_port}")


def create_topology() -> None:

    setLogLevel("info")

    net = Mininet(
        switch=OVSSwitch,
        controller=None,
        link=TCLink
    )

    # ── Switch ──────────────────────────────────────────────────────────────
    s1 = net.addSwitch("s1", failMode="standalone")

    # ── Hosts ────────────────────────────────────────────────────────────────
    h1 = net.addHost("h1", ip="10.0.0.1/24")   # replay
    h2 = net.addHost("h2", ip="10.0.0.2/24")   # destination
    hc = net.addHost("hc", ip="10.0.0.99/24")  # classifier

    # ── Links (order determines port numbers) ────────────────────────────────
    net.addLink(h1, s1, bw=10)   # → s1-eth1  (OF port 1)
    net.addLink(h2, s1, bw=10)   # → s1-eth2  (OF port 2)  QoS here
    net.addLink(hc, s1, bw=10)   # → s1-eth3  (OF port 3)  mirror here

    net.start()
    time.sleep(1)

    # ── QoS on egress toward h2 ──────────────────────────────────────────────
    setup_qos("s1-eth2")

    # ── Default OpenFlow rules ───────────────────────────────────────────────
    setup_default_of_rules("s1")

    # ── Mirror to classifier ─────────────────────────────────────────────────
    setup_mirror("s1", "s1-eth3")

    # ── Verify connectivity ──────────────────────────────────────────────────
    print("\n[Test] Verifying connectivity …\n")
    net.pingAll()

    # ── Summary ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("TOPOLOGY READY")
    print("=" * 60)
    print("\nHosts:")
    print("  h1  10.0.0.1   – PCAP replay host")
    print("  h2  10.0.0.2   – Destination host")
    print("  hc  10.0.0.99  – Classifier / dashboard host")
    print("\nSwitch:  s1  (OVS)")
    print(f"  HTB QoS on {EGRESS_PORT}")
    print("  Traffic mirrored to s1-eth3")
    print("\nUseful commands in the Mininet CLI:")
    print("  Replay PCAP    : h1 tcpreplay --intf1=h1-eth0 capture.pcap")
    print("  Start dashboard: hc python3 dashboard/app.py")
    print("  Show QoS       : sh ovs-vsctl list qos")
    print("  Show queues    : sh ovs-vsctl list queue")
    print("  Dump OF flows  : sh ovs-ofctl dump-flows s1")
    print("=" * 60 + "\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    create_topology()
