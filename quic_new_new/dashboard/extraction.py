#!/usr/bin/env python3
"""
QUIC flow extraction + traffic-class prediction.

Pipeline:
  1. Raw AF_PACKET socket on s1-eth3 captures every mirrored frame.
  2. PerPacketClassifier (packet_classifier.py) decides QUIC / NON_QUIC
     per-flow (buffers first WINDOW_SIZE pkts of a new flow, then caches).
     Only packets labeled QUIC / QUIC_PROBABLE continue past this gate.
  3. Per-flow packets are bucketed into WINDOW_SIZE-second time windows;
     once a window closes, compute_features() builds the traffic-class
     feature vector and model.pkl predicts the class (video/data/web).
  4. The predicted class is pushed to OVS via ovs_qos so future packets
     of that flow get enqueued on the right HTB queue, and ovs_acl
     enforces any blocking rules for that flow/class.
  5. A second, narrow tshark process runs purely as an SNI side-channel
     (quic.dcid -> SNI), since SNI requires decrypting the QUIC Initial's
     TLS ClientHello, which our raw parser does not attempt. SNI plays no
     role in classification or enforcement; it is for display only.
"""

from collections import deque
import subprocess
import threading
import socket
import time
import logging

import numpy as np
import joblib

from packet_classifier import (
    PerPacketClassifier, parse_ethernet, parse_ipv4, parse_udp,
    parse_quic_packet, IPPROTO_UDP, ETH_P_ALL,
)

log = logging.getLogger("extraction")

IFACE = "s1-eth3"

model = joblib.load("model.pkl")

# Import OVS QoS controller (graceful fallback if ovs tools not available)
try:
    import ovs_qos
    OVS_AVAILABLE = True
except ImportError:
    OVS_AVAILABLE = False
    log.warning("ovs_qos module not found – OVS rules will not be installed")

classifier = PerPacketClassifier(model_dir="models/", verbose=False)

WINDOW_SIZE = 5.0
MIN_PACKETS = 5

recent_packets = deque(maxlen=50)
completed_windows = deque(maxlen=500)
prediction_history = deque(maxlen=500)

flows = {}
flow_counter   = 0
packet_counter = 0   # total QUIC packets seen since server start

# ── SNI side-channel (tshark, narrow filter, display-only) ──────────────────
SNI_TSHARK_CMD = [
    "tshark", "-l", "-i", IFACE,
    "-Y", "quic && tls.handshake.type == 1 && tls.handshake.extensions_server_name",
    "-T", "fields",
    "-e", "quic.dcid",
    "-e", "tls.handshake.extensions_server_name",
    "-E", "separator=|",
]

sni_by_cid = {}            # cid (lowercase hex) -> sni
sni_lock = threading.Lock()


def sni_sniffer_thread():
    proc = subprocess.Popen(
        SNI_TSHARK_CMD, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, bufsize=1,
    )
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        parts = line.split("|")
        if len(parts) < 2:
            continue
        cid, sni = parts[0].strip(), parts[1].strip()
        if "," in cid:
            cid = cid.split(",")[0]
        if cid and sni:
            with sni_lock:
                sni_by_cid[cid.lower()] = sni


def lookup_sni(cid: str) -> str:
    if not cid:
        return ""
    with sni_lock:
        return sni_by_cid.get(cid.lower(), "")


# ── Key helpers ───────────────────────────────────────────────────────────────
def make_cid_key(cid: str) -> str:
    return f"cid:{cid.strip().lower()}"


def make_5tuple_key(src_ip, dst_ip, src_port, dst_port, proto):
    ep1 = f"{src_ip.strip()}:{src_port.strip()}"
    ep2 = f"{dst_ip.strip()}:{dst_port.strip()}"
    a, b = sorted([ep1, ep2])
    return f"5t:{a}-{b}/{proto.strip().upper()}"


def is_zero_length_cid(cid: str) -> bool:
    return cid.strip() == ""


# ── Traffic-class feature extraction (unchanged) ────────────────────────────
def compute_features(pkts):
    pkts = sorted(pkts, key=lambda p: p["ts"])

    ts = np.array([p["ts"] for p in pkts])
    lens = np.array([p["udp_len"] for p in pkts])

    iats = np.diff(ts)
    duration = float(ts[-1] - ts[0]) if len(ts) > 1 else 0.0
    total_bytes = int(lens.sum())
    bps = total_bytes / duration if duration > 0 else 0.0

    burst_count = 1 + int((iats > 0.1).sum()) if len(iats) > 0 else 1

    upload_count = sum(1 for p in pkts if p["to_server"])
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


# ── Window-close handler: predict traffic class + push OVS rule + ACL ───────
def process_completed_window(flow_key, flow, socketio=None):
    packets = flow["packets"]
    if len(packets) < MIN_PACKETS:
        return

    features = compute_features(packets)
    feature_vector = [[
        features["packet_count"],
        features["total_bytes"],
        features["duration_s"],
        features["bytes_per_sec"],
        features["mean_payload_len"],
        features["std_payload_len"],
        features["min_payload_len"],
        features["max_payload_len"],
        features["mean_iat"],
        features["std_iat"],
        features["min_iat"],
        features["max_iat"],
        features["burst_count"],
        features["upload_ratio"],
    ]]

    pred = int(model.predict(feature_vector)[0])
    confidence = float(max(model.predict_proba(feature_vector)[0]))

    flow["confidence"] = confidence
    flow["current_class"] = pred
    print(f"CLASS   : {pred}")
    print(f"CONF    : {confidence:.4f}")

    sni = flow.get("sni", "")

    # ── Push real OVS OpenFlow rule for this flow ────────────────────────────
    if OVS_AVAILABLE and ovs_qos._qos_ready:
        sample_pkt = next((p for p in packets if p["to_server"]), packets[-1])

        installed = ovs_qos.apply_flow_classification(
            flow_key=flow_key,
            src_ip=sample_pkt["src_ip"],
            dst_ip=sample_pkt["dst_ip"],
            src_port=sample_pkt["src_port"],
            dst_port=sample_pkt["dst_port"],
            traffic_class=pred,
            socketio=socketio,
        )
        if installed:
            print(f"[OVS]   Flow enqueued → queue {ovs_qos.CLASS_TO_QUEUE.get(pred, 0)}")

        # ── ACL: enforce any blocking rules for this flow ─────────────────
        try:
            import ovs_acl
            ovs_acl.check_and_enforce(
                flow_key=flow_key,
                dst_ip=sample_pkt["dst_ip"],
                src_ip=sample_pkt["src_ip"],
                src_port=sample_pkt["src_port"],
                dst_port=sample_pkt["dst_port"],
                traffic_class=pred,
                socketio=socketio,
            )
        except Exception as _acl_err:
            log.warning("ACL check failed: %s", _acl_err)

    if socketio:
        socketio.emit("flow_update", {
            "flow_id": flow["flow_id"],
            "flow_key": flow_key,
            "current_class": pred,
            "confidence": round(confidence, 4),
            "sni": sni,
        })

    window_data = {
        "flow_id": flow["flow_id"],
        "window_id": flow["window_id"],
        "flow_key": flow_key,
        "start_ts": flow["window_start"],
        "packet_count": features["packet_count"],
        "features": features,
        "predicted_class": pred,
        "confidence": round(confidence, 4),
        "sni": sni,
    }
    completed_windows.append(window_data)

    prediction_history.append({
        "flow_id": flow["flow_id"],
        "window_id": flow["window_id"],
        "predicted_class": pred,
        "confidence": round(confidence, 4),
        "sni": sni,
    })

    if socketio:
        socketio.emit("window", window_data)

    print("\n" + "=" * 70)
    print(f"FLOW ID : {flow['flow_id']}")
    print(f"WINDOW  : {flow['window_id']}")
    print(f"KEY     : {flow_key}")
    print(f"SNI     : {sni or '(unknown)'}")

    if socketio:
        socketio.emit("prediction", {
            "flow_id": flow["flow_id"],
            "window_id": flow["window_id"],
            "predicted_class": pred,
            "confidence": round(confidence, 4),
            "sni": sni,
        })

    for k, v in features.items():
        print(f"{k:20s}: {v}")

    print("=" * 70)


# ── Capture loop: raw socket -> QUIC gate -> windows ─────────────────────────
def start_capture(socketio=None):
    global flow_counter, packet_counter

    threading.Thread(target=sni_sniffer_thread, daemon=True).start()

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((IFACE, 0))
    print(f"\nListening for QUIC traffic on {IFACE} ...\n")

    while True:
        raw, _ = sock.recvfrom(65536)

        result = classifier.process_packet(raw)  # QUIC / NON_QUIC / PENDING / QUIC_PROBABLE / SKIP
        if result['label'] not in ('QUIC', 'QUIC_PROBABLE'):
            continue

        eth = parse_ethernet(raw)
        if eth is None:
            continue
        _, l3 = eth
        ip = parse_ipv4(l3)
        if ip is None or ip['protocol'] != IPPROTO_UDP:
            continue
        udp = parse_udp(ip['ip_payload'])
        if udp is None:
            continue
        src_port, dst_port, udp_payload = udp
        quic_feat = parse_quic_packet(udp_payload)

        ts = time.time()
        src_ip, dst_ip = ip['src_ip'], ip['dst_ip']
        cid = quic_feat['dcid'] or ""
        udp_len = len(udp_payload)

        if not is_zero_length_cid(cid):
            flow_key = make_cid_key(cid)
        else:
            flow_key = make_5tuple_key(src_ip, dst_ip, str(src_port), str(dst_port), "UDP")

        pkt = {
            "ts": ts, "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": str(src_port), "dst_port": str(dst_port),
            "proto": "UDP", "cid": cid, "udp_len": udp_len,
            "to_server": dst_port == 443,
        }

        packet_data = {"ts": ts, "src": src_ip, "dst": dst_ip,
                        "len": udp_len, "dcid": cid, "flow_key": flow_key}
        recent_packets.append(packet_data)
        packet_counter += 1

        if socketio:
            socketio.emit("packet", packet_data)

        # Push real OVS/tc stats to QoS page (throttled to 1/s inside ovs_qos)
        if OVS_AVAILABLE and ovs_qos._qos_ready:
            ovs_qos.push_stats(socketio)

        sni = lookup_sni(cid)

        if flow_key not in flows:
            flow_counter += 1
            flows[flow_key] = {
                "flow_id": flow_counter, "flow_start": ts, "window_start": ts,
                "window_id": 0, "packets": [], "current_class": "DEFAULT",
                "confidence": 0.0, "sni": sni,
            }
            if socketio:
                socketio.emit("flow", {"flow_id": flow_counter, "flow_key": flow_key,
                                        "current_class": "DEFAULT", "sni": sni})

        flow = flows[flow_key]

        # SNI may resolve slightly after flow creation (decryption lag in tshark)
        if sni and not flow.get("sni"):
            flow["sni"] = sni
            if socketio:
                socketio.emit("flow_update", {
                    "flow_id": flow["flow_id"], "flow_key": flow_key,
                    "current_class": flow["current_class"],
                    "confidence": flow["confidence"], "sni": sni,
                })

        if ts - flow["window_start"] >= WINDOW_SIZE:
            process_completed_window(flow_key, flow, socketio)
            flow["packets"] = []
            flow["window_start"] = ts
            flow["window_id"] += 1

        flow["packets"].append(pkt)


if __name__ == "__main__":
    start_capture()
