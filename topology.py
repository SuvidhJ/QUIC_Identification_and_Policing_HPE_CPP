#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI
import subprocess
import time


def setup_qos(egress_port):
    """
    Configure HTB QoS queues on the egress port.
    """

    cmd = (
        f"ovs-vsctl set port {egress_port} qos=@newqos -- "
        f"--id=@newqos create qos type=linux-htb "
        f"other-config:max-rate=10000000 "
        f"queues:0=@q0 queues:1=@q1 queues:2=@q2 queues:3=@q3 -- "
        f"--id=@q0 create queue "
        f"other-config:min-rate=1000000 "
        f"other-config:max-rate=3000000 -- "
        f"--id=@q1 create queue "
        f"other-config:min-rate=4000000 "
        f"other-config:max-rate=8000000 -- "
        f"--id=@q2 create queue "
        f"other-config:min-rate=3000000 "
        f"other-config:max-rate=6000000 -- "
        f"--id=@q3 create queue "
        f"other-config:min-rate=2000000 "
        f"other-config:max-rate=4000000"
    )

    subprocess.run(cmd, shell=True, check=True)

    print("\n[QoS] Configured on", egress_port)
    print(" Queue 0 (VoIP)  : 1-3 Mbps")
    print(" Queue 1 (Video) : 4-8 Mbps")
    print(" Queue 2 (Web)   : 3-6 Mbps")
    print(" Queue 3 (Bulk)  : 2-4 Mbps")


def setup_mirror(switch_name, classifier_port):
    """
    Mirror all traffic to classifier host.
    """

    cmd = (
        f"ovs-vsctl -- set Bridge {switch_name} mirrors=@m "
        f"-- --id=@p get Port {classifier_port} "
        f"-- --id=@m create Mirror "
        f"name=classifier-tap "
        f"select-all=true "
        f"output-port=@p"
    )

    subprocess.run(cmd, shell=True, check=True)

    print(f"[Mirror] Traffic mirrored to {classifier_port}")


def create_topology():

    setLogLevel("info")

    net = Mininet(
        switch=OVSSwitch,
        controller=None,
        link=TCLink
    )

    #
    # Controller
    

    #
    # OVS Switch
    #
    s1 = net.addSwitch("s1",failMode="standalone")

    #
    # Replay Host
    #
    h1 = net.addHost(
        "h1",
        ip="10.0.0.1/24"
    )

    #
    # Destination Host
    #
    h2 = net.addHost(
        "h2",
        ip="10.0.0.2/24"
    )

    #
    # Classifier Host
    #
    hc = net.addHost(
        "hc",
        ip="10.0.0.99/24"
    )

    #
    # Links
    #
    net.addLink(h1, s1, bw=10)   # s1-eth1
    net.addLink(h2, s1, bw=10)   # s1-eth2
    net.addLink(hc, s1, bw=10)   # s1-eth3

    net.start()

    time.sleep(2)

    # #
    # # QoS on egress toward destination
    # #
    # setup_qos("s1-eth2")

    #
    # Mirror traffic to classifier
    #
    setup_mirror("s1", "s1-eth3")

    print("\n[Test] Verifying connectivity...\n")
    net.pingAll()

    print("\n" + "=" * 60)
    print("TOPOLOGY READY")
    print("=" * 60)

    print("\nHosts:")
    print(" h1 (10.0.0.1)  -> PCAP Replay Host")
    print(" h2 (10.0.0.2)  -> Destination Host")
    print(" hc (10.0.0.99) -> Classifier Host")

    print("\nSwitch:")
    print(" s1 -> OVS Switch")
    print(" QoS applied on s1-eth2")
    print(" Traffic mirrored to s1-eth3")

    print("\nUseful Commands:")

    print("\nCapture mirrored traffic:")
    print(" mininet> hc tcpdump -i hc-eth0 -n")

    print("\nReplay PCAP:")
    print(" mininet> h1 tcpreplay --intf1=h1-eth0 capture.pcap")

    print("\nShow OVS configuration:")
    print(" mininet> sh ovs-vsctl show")

    print("\nShow QoS:")
    print(" mininet> sh ovs-vsctl list qos")

    print("\nShow Queues:")
    print(" mininet> sh ovs-vsctl list queue")

    print("\nExit:")
    print(" mininet> exit")

    print("\n" + "=" * 60)

    CLI(net)

    net.stop()


if __name__ == "__main__":
    create_topology()
