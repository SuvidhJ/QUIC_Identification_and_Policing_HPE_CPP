#!/usr/bin/env python3

import subprocess


TSHARK_CMD = [
    "tshark",
    "-l",
    "-i", "s1-eth1",
    "-Y", "quic",
    "-T", "fields",

    "-e", "frame.time_epoch",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "udp.srcport",
    "-e", "udp.dstport",
    "-e", "quic.dcid",
    "-e", "udp.length",

    "-E", "separator=|"
]


def main():

    proc = subprocess.Popen(
        TSHARK_CMD,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

    print("Listening for QUIC packets...\n")

    for line in proc.stdout:

        line = line.strip()

        if not line:
            continue

        parts = line.split("|")

        if len(parts) < 7:
            continue

        ts, src_ip, dst_ip, src_port, dst_port, dcid, udp_len = parts

        print(
            f"TS={ts} "
            f"SRC={src_ip}:{src_port} "
            f"DST={dst_ip}:{dst_port} "
            f"DCID={dcid} "
            f"LEN={udp_len}"
        )


if __name__ == "__main__":
    main()
