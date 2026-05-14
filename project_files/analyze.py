from scapy.all import sniff
from collections import defaultdict
import time
import numpy as np
import pandas as pd
import joblib

# -----------------------------
# CONFIG
# -----------------------------

INTERFACE = "s1-eth1"
FLOW_TIMEOUT = 5
MAX_PACKETS = 20

MODEL_PATH = "qos_model.pkl"

# -----------------------------
# LOAD MODEL
# -----------------------------

model = joblib.load(MODEL_PATH)

FEATURE_COLUMNS = [
    "DURATION",
    "total_packets",
    "total_bytes",
    "packet_rate",
    "packet_rate_rev",
    "byte_rate",
    "byte_rate_rev",
    "direction_ratio",
    "packet_ratio",
    "byte_ratio",
    "avg_rtt",
    "src_jitter",
    "dst_jitter",
    "src_avg_ipt",
    "dst_avg_ipt",
    "packet_burst",
    "PPI_LEN",
    "PPI_DURATION",
    "PPI_ROUNDTRIPS"
]

# -----------------------------
# FLOW STORAGE
# -----------------------------

flows = defaultdict(list)
flow_start_time = {}

# -----------------------------
# FLOW ID
# -----------------------------

def get_flow_id(pkt):
    return (
        pkt["IP"].src,
        pkt["IP"].dst,
        pkt["UDP"].sport,
        pkt["UDP"].dport
    )

# -----------------------------
# FEATURE EXTRACTION
# -----------------------------

def extract_features(packets):
    sizes = np.array([len(p) for p in packets])
    times = np.array([float(p.time) for p in packets])

    iat = np.diff(times) if len(times) > 1 else np.array([0])

    duration = times[-1] - times[0] if len(times) > 1 else 0

    src_ip = packets[0]["IP"].src

    forward = [p for p in packets if p["IP"].src == src_ip]
    backward = [p for p in packets if p["IP"].src != src_ip]

    forward_sizes = np.array([len(p) for p in forward]) if forward else np.array([0])
    backward_sizes = np.array([len(p) for p in backward]) if backward else np.array([0])

    burst_threshold = 0.01
    bursts = iat < burst_threshold

    features = {
        "DURATION": duration,
        "total_packets": len(packets),
        "total_bytes": sizes.sum(),

        "packet_rate": len(packets) / duration if duration > 0 else 0,
        "packet_rate_rev": len(backward) / duration if duration > 0 else 0,

        "byte_rate": sizes.sum() / duration if duration > 0 else 0,
        "byte_rate_rev": backward_sizes.sum() / duration if duration > 0 else 0,

        "direction_ratio": len(forward) / (len(backward) + 1e-6),
        "packet_ratio": len(forward) / (len(backward) + 1e-6),
        "byte_ratio": forward_sizes.sum() / (backward_sizes.sum() + 1e-6),

        "avg_rtt": iat.mean(),

        "src_jitter": np.std(iat),
        "dst_jitter": np.std(iat),

        "src_avg_ipt": iat.mean(),
        "dst_avg_ipt": iat.mean(),

        "packet_burst": bursts.sum(),

        "PPI_LEN": len(packets),
        "PPI_DURATION": duration,
        "PPI_ROUNDTRIPS": len(forward)
    }

    return features

# -----------------------------
# PACKET HANDLER
# -----------------------------

def process_packet(pkt):
    if not pkt.haslayer("IP") or not pkt.haslayer("UDP"):
        return

    flow_id = get_flow_id(pkt)
    now = time.time()

    if flow_id not in flow_start_time:
        flow_start_time[flow_id] = now

    flows[flow_id].append(pkt)

    # condition: enough packets OR timeout
    if (len(flows[flow_id]) >= MAX_PACKETS or
        now - flow_start_time[flow_id] > FLOW_TIMEOUT):

        packets = flows[flow_id]

        features = extract_features(packets)

        df = pd.DataFrame([features])

        # ensure feature order
        X_live = df[FEATURE_COLUMNS].fillna(0)

        prediction = model.predict(X_live)[0]

        print("\n==============================")
        print("Flow:", flow_id)
        print("Features:", features)
        print("Predicted QoS Class:", prediction)
        print("==============================\n")

        # cleanup
        del flows[flow_id]
        del flow_start_time[flow_id]

# -----------------------------
# START SNIFFING
# -----------------------------

print("🚀 Starting Flow Analyzer...")
print(f"📡 Listening on {INTERFACE}\n")

sniff(iface=INTERFACE, prn=process_packet, store=0)