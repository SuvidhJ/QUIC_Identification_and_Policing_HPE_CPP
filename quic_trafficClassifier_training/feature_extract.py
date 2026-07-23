# feature_extract.py
#
# Extracts per-window statistical features from raw QUIC/UDP packet captures
# and pairs each window with a traffic label (video / audio / web / data)
# produced by decrypt.py.

# Flow grouping mirrors decrypt.py exactly:
#   - Primary key : QUIC Destination Connection ID  (quic.dcid)
#   - Fallback key: full 5-tuple when CID is zero-length
#
# Output:
#   training_data.csv  — sessions 1–4
#   test_data.csv      — sessions 5+

import subprocess
import os
import glob
import numpy as np
import pandas as pd
from collections import defaultdict

TSHARK_PATH      = r"C:\Program Files\Wireshark\tshark.exe"
WIRESHARK_PROFILE = "Demo"
RAW_DIR          = "raw2"
DECRYPTED_DIR    = "decrypted"

WINDOW_SIZE = 5.0   # seconds — length of each time slice
MIN_PACKETS = 5     # discard windows with fewer packets (treat as idle noise)


# ===========================================================================
# SECTION 1 — Flow key helpers  (must exactly mirror decrypt.py)
# ===========================================================================
#
# CRITICAL: The keys produced here must be byte-for-byte identical to the
# keys written into the flow_key column by decrypt.py. If they diverge,
# label lookup silently fails and every window gets dropped.

def make_cid_key(cid: str) -> str:
    """
    Primary key: QUIC Destination Connection ID.
    Strips whitespace and lowercases so the string matches what
    decrypt.py stored in the CSV.

    Example output:  "cid:a1b2c3d4e5f60708"
    """
    return f"cid:{cid.strip().lower()}"


def make_5tuple_key(src_ip: str, dst_ip: str,
                    src_port: str, dst_port: str,
                    proto: str) -> str:
    """
    Fallback key: direction-agnostic 5-tuple used when CID length is zero.

    Sorting the two endpoints ensures A→B and B→A packets hash to the
    same key, giving us a bidirectional flow without any special logic.

    Example output:  "5t:192.168.1.5:54231-142.250.80.14:443/UDP"
    """
    ep1 = f"{src_ip.strip()}:{src_port.strip()}"
    ep2 = f"{dst_ip.strip()}:{dst_port.strip()}"
    a, b = sorted([ep1, ep2])
    return f"5t:{a}-{b}/{proto.strip().upper()}"


def is_zero_length_cid(cid: str) -> bool:
    """tshark emits an empty string for zero-length CIDs."""
    return cid.strip() == ""


# ===========================================================================
# SECTION 2 — Packet extraction from pcap via tshark
# ===========================================================================

def extract_packets(pcap_path: str) -> list[dict]:
    """
    Run tshark once against the pcap and pull out one row per UDP packet.

    Fields extracted:
      frame.time_epoch  — absolute Unix timestamp in seconds (float)
      ip.src / ip.dst   — source and destination IP addresses
      udp.srcport /
      udp.dstport       — UDP ports (QUIC always runs over UDP)
      ip.proto          — IP protocol number; always 17 (UDP) here but
                          needed to build a 5-tuple key that matches decrypt.py
      quic.dcid         — QUIC Destination Connection ID from the packet header;
                          empty string if the server negotiated zero-length CIDs
      udp.length        — UDP payload length in bytes; used as the packet size
                          feature (includes UDP header, which is 8 bytes, so
                          actual QUIC payload = udp.length - 8, but we keep the
                          raw value for consistency across all packets)

    Why udp.length and not frame.len?
      frame.len includes Ethernet + IP headers which are constant overhead and
      add no information about QUIC traffic patterns. udp.length reflects the
      actual data the application put on the wire.

    Returns a list of dicts, one per valid packet.
    Empty or malformed lines are silently skipped.
    """
    cmd = [
        TSHARK_PATH,
        "-C", WIRESHARK_PROFILE,
        "-r", pcap_path,
        "-Y", "quic",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "ip.proto",          # NEW — needed for 5-tuple key
        "-e", "quic.dcid",         # NEW — primary flow key
        "-e", "udp.length",
        "-E", "separator=\t",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)

    packets = []
    for line in result.stdout.strip().split("\n"):
        parts = line.split("\t")
        if len(parts) < 8:
            continue  # skip non-UDP or malformed lines

        ts, src_ip, dst_ip, src_port, dst_port, proto, cid, udp_len = parts[:8]

        try:
            ts      = float(ts)
            udp_len = int(udp_len)
        except ValueError:
            continue  # skip lines where numeric fields didn't parse

        packets.append({
            "ts":       ts,
            "src_ip":   src_ip.strip(),
            "dst_ip":   dst_ip.strip(),
            "src_port": src_port.strip(),
            "dst_port": dst_port.strip(),
            "proto":    proto.strip(),
            "cid":      cid.strip(),
            "udp_len":  udp_len,
            "to_server": dst_port.strip() == "443"
        })

    return packets


# ===========================================================================
# SECTION 3 — Group packets into flows
# ===========================================================================

def group_into_flows(packets: list[dict]) -> dict[str, list[dict]]:
    """
    Assign each packet to a flow using the same key logic as decrypt.py.

    For each packet:
      - If quic.dcid is non-empty  → key = "cid:<dcid>"
      - If quic.dcid is empty      → key = "5t:<sorted endpoints>/<proto>"

    Returns a dict:  flow_key → list of packet dicts

    Why not just group by 5-tuple always?
      A QUIC connection can migrate from one IP to another mid-stream.
      When that happens the 5-tuple changes but the CID stays the same.
      Grouping by CID keeps those packets in one flow; grouping by 5-tuple
      would split them into two flows, producing features that don't
      represent any real single connection.
    """
    flows = defaultdict(list)

    for pkt in packets:
        if not is_zero_length_cid(pkt["cid"]):
            key = make_cid_key(pkt["cid"])
        else:
            key = make_5tuple_key(
                pkt["src_ip"], pkt["dst_ip"],
                pkt["src_port"], pkt["dst_port"],
                pkt["proto"]
            )
        flows[key].append(pkt)

    return flows


# ===========================================================================
# SECTION 4 — Label loading
# ===========================================================================

def load_labels(labels_csv: str) -> dict[str, str]:
    """
    Read the CSV produced by decrypt.py and return a dict:
      flow_key (string) → label (string)

    The flow_key column already contains the full key string
    (e.g. "cid:a1b2c3..." or "5t:...") so no reconstruction is needed —
    we just index it directly.

    Why not re-derive the key from ip_a/ip_b as before?
      The old code re-derived a 2-tuple key from ip_a and ip_b at load time.
      That was fragile and tied label lookup to IP addresses, which change
      during IP migration. Now the flow_key column IS the canonical key,
      so we use it directly. This is simpler and correct for CID-keyed flows.
    """
    df = pd.read_csv(labels_csv)

    # Validate that the new column schema is present
    required = {"flow_key", "label"}
    missing  = required - set(df.columns)
    if missing:
        raise ValueError(
            f"labels CSV is missing columns: {missing}. "
            f"Re-run decrypt.py to regenerate it."
        )

    return dict(zip(df["flow_key"], df["label"]))


# ===========================================================================
# SECTION 5 — Time-window slicing
# ===========================================================================

def window_packets(pkts: list[dict]) -> list[list[dict]]:
    """
    Slice a flow's packet list into fixed-length time windows.

    Why fixed time windows instead of fixed packet counts?
      Traffic classification models need a consistent time horizon.
      A fixed packet count window would be short during bursts and long
      during idle periods, making features like bytes_per_sec meaningless.
      A fixed time window always represents the same real-world duration.

    Algorithm:
      Sort packets by timestamp, then walk forward. When a packet falls
      outside [t_start, t_start + WINDOW_SIZE], flush the current window
      (if it has >= MIN_PACKETS) and start a new one from that packet.

    MIN_PACKETS guard:
      Windows with fewer than MIN_PACKETS packets are discarded. These
      represent idle periods where the connection was quiet. Including them
      would pollute the feature distribution with near-zero byte-rate windows
      that don't reflect any actual streaming behavior.

    Returns a list of windows, each window being a list of packet dicts.
    """
    if not pkts:
        return []

    pkts    = sorted(pkts, key=lambda p: p["ts"])
    windows = []
    current = []
    t_start = pkts[0]["ts"]

    for p in pkts:
        if p["ts"] - t_start <= WINDOW_SIZE:
            current.append(p)
        else:
            if len(current) >= MIN_PACKETS:
                windows.append(current)
            current = [p]
            t_start = p["ts"]

    if len(current) >= MIN_PACKETS:
        windows.append(current)

    return windows


# ===========================================================================
# SECTION 6 — Feature computation
# ===========================================================================

def compute_features(pkts: list[dict]) -> dict:
    """
    Compute statistical features from one time window of packets.

    All features are derived purely from packet metadata visible in the
    encrypted QUIC header — no payload inspection required. This matters
    because QUIC encrypts everything except the CID and packet number,
    so payload-based features are unavailable.

    Features computed:

    VOLUME features:
      packet_count      — total number of packets in the window
      total_bytes       — sum of UDP payload lengths (bytes on the wire)
      duration_s        — time from first to last packet in the window
      bytes_per_sec     — total_bytes / duration_s; primary throughput signal.
                          Video streaming has a very different bps profile
                          than web browsing or signaling traffic.

    PACKET SIZE features (from udp.length distribution):
      mean_payload_len  — average packet size. Video typically has many
                          large packets near MTU (1350–1460 bytes).
      std_payload_len   — size variance. Highly variable sizes suggest
                          mixed content (headers + data). Low variance
                          suggests a steady stream of same-size chunks.
      min_payload_len   — smallest packet; small values indicate ACKs or
                          control frames mixed in with data.
      max_payload_len   — largest packet; near-MTU values confirm large
                          data transfer (video/audio chunks).

    INTER-ARRIVAL TIME (IAT) features (from np.diff on timestamps):
      mean_iat          — average gap between packets. Low mean = high
                          packet rate = likely streaming or bulk transfer.
      std_iat           — IAT variance. Bursty traffic (video chunk fetches)
                          has high std_iat. Smooth streaming has low std_iat.
      min_iat           — smallest gap; near-zero values indicate back-to-back
                          packets within the same burst.
      max_iat           — largest gap; long pauses indicate buffering or idle.

    BURST feature:
      burst_count       — number of bursts, defined as groups of packets
                          separated by gaps > 100 ms. Each gap > 100ms
                          starts a new burst. This captures the chunk-fetch
                          pattern typical of adaptive bitrate video streaming:
                          fetch a 2-second chunk quickly, pause, fetch next.

    DIRECTION feature:
      upload_ratio      — fraction of packets going client→server
                          (identified by dst_port == "443").
                          Video consumption is heavily download-skewed
                          (low upload_ratio). Video calls or uploads are
                          more balanced (higher upload_ratio).
    """
    pkts = sorted(pkts, key=lambda p: p["ts"])
    ts   = np.array([p["ts"]      for p in pkts])
    lens = np.array([p["udp_len"] for p in pkts])
    iats = np.diff(ts)   # N-1 inter-arrival times for N packets

    duration    = float(ts[-1] - ts[0]) if len(ts) > 1 else 0.0
    total_bytes = int(lens.sum())
    bps         = total_bytes / duration if duration > 0 else 0.0

    # burst_count: every IAT > 100ms starts a new burst
    # The +1 accounts for the first burst (which has no preceding gap)
    burst_count = 1 + int((iats > 0.1).sum()) if len(iats) > 0 else 1

    upload_count = sum(1 for p in pkts if p["to_server"])
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


# ===========================================================================
# SECTION 7 — Per-file orchestration
# ===========================================================================

def process_pcap(pcap_path: str, labels_csv: str) -> pd.DataFrame:
    """
    Full pipeline for a single pcap:
      1. Load labels from decrypt.py output CSV.
      2. Extract all packets from the pcap via tshark.
      3. Group packets into flows using CID / 5-tuple keys.
      4. For each flow that has a label, slice into time windows.
      5. Compute features for each window.
      6. Return a DataFrame of all windows from this pcap.

    The pcap basename (without extension) is recorded in the 'source'
    column so every row can be traced back to its origin file, regardless
    of what the filename actually is.

    Flows with no matching label are silently skipped — this is expected
    for background traffic (OS updates, telemetry, etc.) that decrypt.py
    didn't encounter any HTTP/3 or TLS SNI packets for.
    """
    # Derive a human-readable source name directly from the filename.
    # e.g. "youtube_session1.pcap" → "youtube_session1"
    #      "capture_2024_01_15.pcap" → "capture_2024_01_15"
    source = os.path.splitext(os.path.basename(pcap_path))[0]

    labels  = load_labels(labels_csv)
    packets = extract_packets(pcap_path)

    print(f"    [debug] {len(labels)} flows labeled, {len(packets)} packets extracted")

    if not packets:
        return pd.DataFrame()

    flows = group_into_flows(packets)

    matched = sum(1 for k in flows if k in labels)
    print(f"    [debug] {len(flows)} flows found, {matched} matched to labels")

    rows = []
    for flow_key, pkts in flows.items():
        if flow_key not in labels:
            continue

        label   = labels[flow_key]
        windows = window_packets(pkts)

        for w_idx, window in enumerate(windows):
            features = compute_features(window)

            # Attach metadata columns so the final CSV is self-contained
            # and you can trace any row back to its source pcap and flow.
            features["source"]    = source        # pcap basename, no extension
            features["flow_key"]  = flow_key      # full key for debugging
            features["window"]    = w_idx
            features["label"]     = label
            rows.append(features)

    print(f"    [debug] {len(rows)} windows generated")
    return pd.DataFrame(rows)


# ===========================================================================
# SECTION 8 — Entry point
# ===========================================================================

def main():
    """
    Scan raw/ for all *.pcap files and process each one.

    Filename format: anything ending in .pcap.
    The matching labels CSV is expected to live in DECRYPTED_DIR with
    the same basename and a _labels.csv suffix:

        raw/youtube_session1.pcap     →  decrypted/youtube_session1_labels.csv
        raw/capture_2024_01_15.pcap   →  decrypted/capture_2024_01_15_labels.csv
        raw/twitch_hd_run3.pcap       →  decrypted/twitch_hd_run3_labels.csv

    All windows from all files are concatenated into one output CSV:
        all_data.csv

    If you need a train/test split, do it downstream (e.g. in your model
    training script) using the 'source' column to group by capture file.
    """
    pcap_files = sorted(glob.glob(os.path.join(RAW_DIR, "*.pcap")))
    if not pcap_files:
        print(f"[!] no pcap files in {RAW_DIR}/")
        return

    all_dfs = []

    for pcap_path in pcap_files:
        fname  = os.path.basename(pcap_path)
        base   = os.path.splitext(fname)[0]          # strip .pcap
        labels_csv = os.path.join(DECRYPTED_DIR, f"{base}_labels.csv")

        if not os.path.exists(labels_csv):
            print(f"[!] labels not found for {fname} — run decrypt.py first")
            continue

        print(f"\n[*] processing {fname}")
        df = process_pcap(pcap_path, labels_csv)

        if df.empty:
            print(f"    -> 0 windows, skipping")
            continue

        print(f"    -> {len(df)} windows")
        all_dfs.append(df)

    # Column order for the output CSV.
    # 'source' replaces the old 'service' + 'session' columns — it's just
    # the pcap basename, which carries whatever naming convention you used.
    col_order = [
        "source", "window", "flow_key",
        "packet_count", "total_bytes", "duration_s", "bytes_per_sec",
        "mean_payload_len", "std_payload_len", "min_payload_len", "max_payload_len",
        "mean_iat", "std_iat", "min_iat", "max_iat",
        "burst_count", "upload_ratio",
        "label",
    ]

    if all_dfs:
        out_df = pd.concat(all_dfs, ignore_index=True)[col_order]
        out_df.to_csv("all_data.csv", index=False)
        print(f"\n[*] all_data.csv : {len(out_df)} rows")
        print(out_df["label"].value_counts().to_string())
        print(f"\n[*] rows per source file:")
        print(out_df["source"].value_counts().to_string())
    else:
        print("\n[!] no data generated")


if __name__ == "__main__":
    main()