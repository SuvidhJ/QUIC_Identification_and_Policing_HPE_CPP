# feature_extract.py
import subprocess
import os
import glob
import re
import numpy as np
import pandas as pd
from collections import defaultdict, Counter

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
WIRESHARK_PROFILE = "Demo"
RAW_DIR = "raw"
DECRYPTED_DIR = "decrypted"

WINDOW_SIZE = 5.0   # seconds per window
MIN_PACKETS = 5     # drop windows with fewer packets (idle)

def extract_packets(pcap_path):
    cmd = [
        TSHARK_PATH,
        "-C", WIRESHARK_PROFILE,
        "-r", pcap_path,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "udp.length",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    packets = []
    for line in result.stdout.strip().split("\n"):
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        ts, src_ip, dst_ip, src_port, dst_port, udp_len = parts[:6]
        try:
            ts = float(ts)
            udp_len = int(udp_len)
        except ValueError:
            continue
        packets.append({
            "ts":       ts,
            "src_ip":   src_ip.strip(),
            "dst_ip":   dst_ip.strip(),
            "src_port": src_port.strip(),
            "dst_port": dst_port.strip(),
            "udp_len":  udp_len,
        })
    return packets

def window_packets(pkts):
    """Slice a flow's packets into WINDOW_SIZE second windows."""
    if not pkts:
        return []
    pkts = sorted(pkts, key=lambda p: p["ts"])
    windows = []
    current = []
    t_start = pkts[0]["ts"]
    for p in pkts:
        if p["ts"] - t_start <= WINDOW_SIZE:
            current.append(p)
        else:
            if len(current) >= MIN_PACKETS:
                windows.append(current)
            # start new window
            current = [p]
            t_start = p["ts"]
    if len(current) >= MIN_PACKETS:
        windows.append(current)
    return windows

def compute_features(pkts):
    pkts = sorted(pkts, key=lambda p: p["ts"])
    ts   = np.array([p["ts"]      for p in pkts])
    lens = np.array([p["udp_len"] for p in pkts])
    iats = np.diff(ts)

    duration    = float(ts[-1] - ts[0]) if len(ts) > 1 else 0.0
    total_bytes = int(lens.sum())
    bps         = total_bytes / duration if duration > 0 else 0.0

    # burst = group of packets with IAT < 100ms
    burst_count  = 1 + int((iats > 0.1).sum()) if len(iats) > 0 else 1

    # upload ratio: packets going TO port 443 (client -> server)
    upload_count = sum(1 for p in pkts if p["dst_port"] == "443")
    upload_ratio = upload_count / len(pkts)

    return {
        "packet_count":     len(pkts),
        "total_bytes":      total_bytes,
        "duration_s":       round(duration, 4),
        "bytes_per_sec":    round(bps, 2),
        "mean_payload_len": round(float(lens.mean()), 2),
        "std_payload_len":  round(float(lens.std()),  2),
        "min_payload_len":  int(lens.min()),
        "max_payload_len":  int(lens.max()),
        "mean_iat":         round(float(iats.mean()), 6) if len(iats) else 0.0,
        "std_iat":          round(float(iats.std()),  6) if len(iats) else 0.0,
        "min_iat":          round(float(iats.min()),  6) if len(iats) else 0.0,
        "max_iat":          round(float(iats.max()),  6) if len(iats) else 0.0,
        "burst_count":      burst_count,
        "upload_ratio":     round(upload_ratio, 4),
    }

def load_labels(labels_csv):
    """Load ip_a, ip_b -> label mapping (direction-agnostic)."""
    df = pd.read_csv(labels_csv)
    labels = {}
    for _, row in df.iterrows():
        key = tuple(sorted([row["ip_a"], row["ip_b"]]))
        labels[key] = row["label"]
    return labels

def process_pcap(pcap_path, labels_csv, service, session_num):
    labels  = load_labels(labels_csv)
    packets = extract_packets(pcap_path)

    print(f"    [debug] {len(labels)} ip pairs labeled, {len(packets)} packets")

    if not packets:
        return pd.DataFrame()

    # group into bidirectional flows using sorted ip pair as key
    flows = defaultdict(list)
    for pkt in packets:
        key = tuple(sorted([pkt["src_ip"], pkt["dst_ip"]]))
        flows[key].append(pkt)

    print(f"    [debug] {len(flows)} bidirectional flows, "
          f"{len([k for k in flows if k in labels])} matched to labels")

    rows = []
    for key, pkts in flows.items():
        if key not in labels:
            continue

        label   = labels[key]
        windows = window_packets(pkts)

        for w_idx, window in enumerate(windows):
            features = compute_features(window)
            features["service"]  = service
            features["session"]  = session_num
            features["ip_a"]     = key[0]
            features["ip_b"]     = key[1]
            features["window"]   = w_idx
            features["label"]    = label
            rows.append(features)

    print(f"    [debug] {len(rows)} windows generated")
    return pd.DataFrame(rows)

def main():
    pcap_files = sorted(glob.glob(os.path.join(RAW_DIR, "*.pcap")))
    if not pcap_files:
        print(f"[!] no pcap files in {RAW_DIR}/")
        return

    train_dfs = []
    test_dfs  = []

    for pcap_path in pcap_files:
        fname = os.path.basename(pcap_path)
        match = re.match(r"(.+)_session(\d+)\.pcap", fname)
        if not match:
            print(f"[!] skipping {fname} - unexpected filename format")
            continue

        service     = match.group(1)
        session_num = int(match.group(2))
        labels_csv  = os.path.join(DECRYPTED_DIR, f"{service}_session{session_num}_labels.csv")

        if not os.path.exists(labels_csv):
            print(f"[!] labels not found for {fname}, run decrypt.py first")
            continue

        print(f"[*] processing {fname} (service={service}, session={session_num})...")
        df = process_pcap(pcap_path, labels_csv, service, session_num)

        if df.empty:
            print(f"    -> 0 windows, skipping")
            continue

        print(f"    -> {len(df)} windows")
        if session_num <= 4:
            train_dfs.append(df)
        else:
            test_dfs.append(df)

    col_order = [
        "service", "session", "window", "ip_a", "ip_b",
        "packet_count", "total_bytes", "duration_s", "bytes_per_sec",
        "mean_payload_len", "std_payload_len", "min_payload_len", "max_payload_len",
        "mean_iat", "std_iat", "min_iat", "max_iat",
        "burst_count", "upload_ratio", "label"
    ]

    if train_dfs:
        train_df = pd.concat(train_dfs, ignore_index=True)[col_order]
        train_df.to_csv("training_data.csv", index=False)
        print(f"\n[*] training_data.csv : {len(train_df)} rows")
        print(train_df["label"].value_counts().to_string())
    else:
        print("[!] no training data generated")

    if test_dfs:
        test_df = pd.concat(test_dfs, ignore_index=True)[col_order]
        test_df.to_csv("test_data.csv", index=False)
        print(f"\n[*] test_data.csv     : {len(test_df)} rows")
        print(test_df["label"].value_counts().to_string())
    else:
        print("[!] no test data yet")

if __name__ == "__main__":
    main()