#!/usr/bin/env python3

from collections import deque
import subprocess
import numpy as np

WINDOW_SIZE = 5.0
MIN_PACKETS = 5

recent_packets = deque(maxlen=50)
completed_windows = deque(maxlen=100)

flows = {}
flow_counter = 0


def make_cid_key(cid: str) -> str:
    return f"cid:{cid.strip().lower()}"


def make_5tuple_key(src_ip, dst_ip, src_port, dst_port, proto):
    ep1 = f"{src_ip.strip()}:{src_port.strip()}"
    ep2 = f"{dst_ip.strip()}:{dst_port.strip()}"

    a, b = sorted([ep1, ep2])

    return f"5t:{a}-{b}/{proto.strip().upper()}"


def is_zero_length_cid(cid: str) -> bool:
    return cid.strip() == ""


def compute_features(pkts):

    pkts = sorted(pkts, key=lambda p: p["ts"])

    ts = np.array([p["ts"] for p in pkts])
    lens = np.array([p["udp_len"] for p in pkts])

    iats = np.diff(ts)

    duration = float(ts[-1] - ts[0]) if len(ts) > 1 else 0.0

    total_bytes = int(lens.sum())

    bps = total_bytes / duration if duration > 0 else 0.0

    burst_count = (
        1 + int((iats > 0.1).sum())
        if len(iats) > 0
        else 1
    )

    upload_count = sum(
        1
        for p in pkts
        if p["to_server"]
    )

    upload_ratio = upload_count / len(pkts)

    return {
        "packet_count": len(pkts),
        "total_bytes": total_bytes,
        "duration_s": round(duration, 4),
        "bytes_per_sec": round(bps, 2),

        "mean_payload_len": round(float(lens.mean()), 2),
        "std_payload_len": round(float(lens.std()), 2),
        "min_payload_len": int(lens.min()),
        "max_payload_len": int(lens.max()),

        "mean_iat": round(float(iats.mean()), 6) if len(iats) else 0.0,
        "std_iat": round(float(iats.std()), 6) if len(iats) else 0.0,
        "min_iat": round(float(iats.min()), 6) if len(iats) else 0.0,
        "max_iat": round(float(iats.max()), 6) if len(iats) else 0.0,

        "burst_count": burst_count,
        "upload_ratio": round(upload_ratio, 4),
    }


TSHARK_CMD = [
    "tshark",
    "-l",
    "-i",
    "s1-eth1",

    "-Y",
    "quic",

    "-T",
    "fields",

    "-e",
    "frame.time_epoch",

    "-e",
    "ip.src",

    "-e",
    "ip.dst",

    "-e",
    "udp.srcport",

    "-e",
    "udp.dstport",

    "-e",
    "ip.proto",

    "-e",
    "quic.dcid",

    "-e",
    "udp.length",

    "-E",
    "separator=|"
]


def process_completed_window(flow_key, flow):

    packets = flow["packets"]

    if len(packets) < MIN_PACKETS:
        return

    features = compute_features(packets)

    completed_windows.append({
        "flow_id": flow["flow_id"],
        "window_id": flow["window_id"],
        "flow_key": flow_key,
        "start_ts": flow["window_start"],
        "packet_count": features["packet_count"],
        "features": features
    })

    print("\n" + "=" * 70)
    print(f"FLOW ID : {flow['flow_id']}")
    print(f"WINDOW  : {flow['window_id']}")
    print(f"KEY     : {flow_key}")

    for k, v in features.items():
        print(f"{k:20s}: {v}")

    print("=" * 70)


def main():

    global flow_counter

    proc = subprocess.Popen(
        TSHARK_CMD,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

    print("\nListening for QUIC traffic...\n")

    for line in proc.stdout:

        line = line.strip()

        if not line:
            continue

        parts = line.split("|")

        if len(parts) < 8:
            continue

        (
            ts,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
            cid,
            udp_len
        ) = parts

        try:
            ts = float(ts)
            udp_len = int(udp_len)
        except:
            continue

        if "," in cid:
            cid = cid.split(",")[0]

        cid = cid.strip()

        if not is_zero_length_cid(cid):

            flow_key = make_cid_key(cid)

        else:

            flow_key = make_5tuple_key(
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                proto
            )

        pkt = {
            "ts": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto,
            "cid": cid,
            "udp_len": udp_len,
            "to_server": dst_port == "443"
        }

        recent_packets.append({
            "ts": ts,
            "src": src_ip,
            "dst": dst_ip,
            "len": udp_len,
            "dcid": cid,
            "flow_key": flow_key
        })

        if flow_key not in flows:

            flow_counter += 1

            flows[flow_key] = {
                "flow_id": flow_counter,
                "flow_start": ts,
                "window_start": ts,
                "window_id": 0,
                "packets": []
            }

        flow = flows[flow_key]

        if ts - flow["window_start"] > WINDOW_SIZE:

            process_completed_window(
                flow_key,
                flow
            )

            flow["packets"] = []
            flow["window_start"] = ts
            flow["window_id"] += 1

        flow["packets"].append(pkt)


if __name__ == "__main__":
    main()
