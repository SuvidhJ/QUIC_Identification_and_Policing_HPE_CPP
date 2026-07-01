#!/usr/bin/env python3
"""
pcap_compare.py
─────────────────────────────────────────────────────────────────────────────
Offline, isolated test: replay a .pcap through OUR classifier (the same
parse_ethernet/parse_ipv4/parse_udp/parse_quic_packet + QUICDetector logic
used live in packet_classifier.py) and INDEPENDENTLY ask tshark what it
thinks each packet is. Print a full per-packet comparison table plus a
confusion-matrix / accuracy report.

This is NOT part of the live pipeline — it's a standalone correctness check
against ground truth, run once against a captured pcap.

Usage:
    python3 pcap_compare.py capture.pcap --model-dir models/
    python3 pcap_compare.py capture.pcap --model-dir models/ --csv out.csv
    python3 pcap_compare.py capture.pcap --model-dir models/ --limit 5000

Requires: tshark installed and on PATH. No scapy/dpkt — pcap is parsed with
pure stdlib `struct`, reusing the exact parsing code your live pipeline uses.
"""

import argparse
import struct
import subprocess
import sys
from collections import defaultdict

from packet_classifier import (
    PerPacketClassifier, parse_ethernet, parse_ipv4, parse_udp,
    IPPROTO_UDP, IPPROTO_TCP,
)

# ─────────────────────────────────────────────────────────────────────────────
# Minimal pure-stdlib pcap (classic libpcap, not pcapng) frame reader
# ─────────────────────────────────────────────────────────────────────────────

PCAP_MAGIC_LE = 0xa1b2c3d4
PCAP_MAGIC_LE_NS = 0xa1b23c4d
PCAP_MAGIC_BE = 0xd4c3b2a1
PCAP_MAGIC_BE_NS = 0x4d3cb2a1


def read_pcap_frames(path: str):
    """
    Yield (frame_index, timestamp_float, raw_bytes) for each frame in a
    classic-format .pcap file. Handles both byte orders and us/ns timestamp
    resolution. Does NOT support pcapng (.pcapng) — convert first with
    `tshark -F pcap -r in.pcapng -w out.pcap` if needed.
    """
    with open(path, "rb") as f:
        global_hdr = f.read(24)
        if len(global_hdr) < 24:
            raise ValueError("File too short to be a valid pcap")

        magic = struct.unpack_from("<I", global_hdr, 0)[0]
        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_LE_NS):
            endian = "<"
        else:
            magic_be = struct.unpack_from(">I", global_hdr, 0)[0]
            if magic_be in (PCAP_MAGIC_BE, PCAP_MAGIC_BE_NS):
                endian = ">"
            else:
                raise ValueError(
                    f"Not a recognized classic pcap file (magic={magic:#x}). "
                    "If this is pcapng, convert first: "
                    "tshark -F pcap -r in.pcapng -w out.pcap"
                )

        ns_resolution = magic in (PCAP_MAGIC_LE_NS, PCAP_MAGIC_BE_NS)

        idx = 0
        while True:
            rec_hdr = f.read(16)
            if len(rec_hdr) < 16:
                break
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", rec_hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            ts = ts_sec + (ts_frac / 1_000_000_000.0 if ns_resolution else ts_frac / 1_000_000.0)
            yield idx, ts, data
            idx += 1


# ─────────────────────────────────────────────────────────────────────────────
# Ground truth via tshark (independent process, reads the same pcap)
# ─────────────────────────────────────────────────────────────────────────────

def get_tshark_ground_truth(pcap_path: str):
    """
    Returns a dict: frame_number (1-based, matching tshark's frame.number)
    -> 'QUIC' or 'NON_QUIC', based on tshark's own protocol dissection.
    """
    cmd = [
        "tshark", "-nr", pcap_path,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.protocols",
        "-E", "separator=|",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        sys.exit("[!] tshark not found on PATH. Install it: sudo apt install tshark")
    except subprocess.CalledProcessError as e:
        sys.exit(f"[!] tshark failed: {e.stderr}")

    gt = {}
    for line in proc.stdout.splitlines():
        parts = line.strip().split("|")
        if len(parts) < 2:
            continue
        try:
            frame_no = int(parts[0])
        except ValueError:
            continue
        gt[frame_no] = "QUIC" if "quic" in parts[1].lower() else "NON_QUIC"
    return gt


# ─────────────────────────────────────────────────────────────────────────────
# Run our classifier over every frame
# ─────────────────────────────────────────────────────────────────────────────

def classify_pcap(pcap_path: str, model_dir: str, limit: int = None):
    """
    Returns a list of row dicts:
      frame_no, ts, five_tuple_str, our_label, our_conf, our_tier, our_reason
    our_label is one of QUIC / NON_QUIC / QUIC_PROBABLE / PENDING / SKIP
    """
    classifier = PerPacketClassifier(model_dir=model_dir, verbose=False)
    rows = []

    for idx, ts, raw in read_pcap_frames(pcap_path):
        if limit is not None and idx >= limit:
            break

        result = classifier.process_packet(raw)
        ft = result["five_tuple"]
        ft_str = f"{ft[0]}:{ft[2]} <-> {ft[1]}:{ft[3]} [{ft[4]}]" if ft else "-"

        rows.append({
            "frame_no": idx + 1,           # align with tshark's 1-based frame.number
            "ts": ts,
            "five_tuple": ft_str,
            "our_label": result["label"],
            "our_conf": result["confidence"],
            "our_tier": result["tier"],
            "our_reason": result["reason"],
        })

    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Scoring (PENDING counts as NON_QUIC for the metric, but is shown as PENDING)
# ─────────────────────────────────────────────────────────────────────────────

def score(rows, gt):
    counts = defaultdict(int)   # TP, TN, FP, FN
    unmatched = 0

    for row in rows:
        gt_label = gt.get(row["frame_no"])
        if gt_label is None:
            unmatched += 1
            row["tshark_label"] = "?"
            row["match"] = None
            continue

        row["tshark_label"] = gt_label

        pred_for_scoring = "QUIC" if row["our_label"] in ("QUIC", "QUIC_PROBABLE") else "NON_QUIC"

        if gt_label == "QUIC" and pred_for_scoring == "QUIC":
            counts["TP"] += 1
        elif gt_label == "NON_QUIC" and pred_for_scoring == "NON_QUIC":
            counts["TN"] += 1
        elif gt_label == "NON_QUIC" and pred_for_scoring == "QUIC":
            counts["FP"] += 1
        else:
            counts["FN"] += 1

        row["match"] = (gt_label == pred_for_scoring)

    return counts, unmatched


# ─────────────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────────────

def print_table(rows, only_mismatches=False):
    header = f'{"#":>6}  {"time":>12}  {"our_label":<14} {"tshark":<9} {"match":<6} {"5-tuple":<55} reason'
    print(header)
    print("-" * len(header))
    for row in rows:
        if only_mismatches and row.get("match") in (True, None):
            continue
        match_str = "✔" if row.get("match") else ("✘" if row.get("match") is False else "-")
        print(
            f'{row["frame_no"]:>6}  {row["ts"]:>12.6f}  '
            f'{row["our_label"]:<14} {row.get("tshark_label","?"):<9} {match_str:<6} '
            f'{row["five_tuple"]:<55} {row["our_reason"]}'
        )


def print_metrics(counts, unmatched, total_rows):
    tp, tn, fp, fn = counts["TP"], counts["TN"], counts["FP"], counts["FN"]
    scored = tp + tn + fp + fn
    accuracy  = (tp + tn) / scored if scored else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    print("\n" + "=" * 60)
    print("CONFUSION MATRIX  (positive class = QUIC)")
    print("=" * 60)
    print(f'{"":15}{"tshark: QUIC":>15}{"tshark: NON_QUIC":>20}')
    print(f'{"ours: QUIC":15}{tp:>15}{fp:>20}   <- predicted QUIC')
    print(f'{"ours: NON_QUIC":15}{fn:>15}{tn:>20}   <- predicted NON_QUIC')
    print("-" * 60)
    print(f"TP={tp}  TN={tn}  FP={fp}  FN={fn}")
    print(f"Total packets in pcap : {total_rows}")
    print(f"Scored (had GT label) : {scored}")
    print(f"Unmatched (no GT)      : {unmatched}")
    print("-" * 60)
    print(f"Accuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1 score  : {f1:.4f}")
    print("=" * 60)


def write_csv(rows, path):
    import csv
    fields = ["frame_no", "ts", "five_tuple", "our_label", "our_conf",
              "our_tier", "our_reason", "tshark_label", "match"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k) for k in fields})
    print(f"\n[*] Full per-packet comparison written to {path}")


def main():
    ap = argparse.ArgumentParser(description="Compare our QUIC classifier vs tshark on a pcap")
    ap.add_argument("pcap", help="Path to .pcap file (classic format, not pcapng)")
    ap.add_argument("--model-dir", default="models/", help="Dir with best_model.pkl + metadata.json")
    ap.add_argument("--limit", type=int, default=None, help="Only process first N frames")
    ap.add_argument("--csv", default=None, help="Write full per-packet table to this CSV path")
    ap.add_argument("--output", default="comparison_report.txt",
                     help="Write the printed table + metrics to this text file "
                          "(default: comparison_report.txt). Use '-' to print to "
                          "stdout only, no file.")
    ap.add_argument("--mismatches-only", action="store_true",
                     help="Only print rows where our label disagrees with tshark")
    args = ap.parse_args()

    print(f"[*] Reading {args.pcap} ...")
    rows = classify_pcap(args.pcap, args.model_dir, limit=args.limit)
    print(f"[*] {len(rows)} frames parsed. Asking tshark for ground truth...")

    gt = get_tshark_ground_truth(args.pcap)
    counts, unmatched = score(rows, gt)

    if args.output == "-":
        print_table(rows, only_mismatches=args.mismatches_only)
        print_metrics(counts, unmatched, len(rows))
    else:
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_table(rows, only_mismatches=args.mismatches_only)
            print_metrics(counts, unmatched, len(rows))
        report_text = buf.getvalue()

        with open(args.output, "w") as f:
            f.write(report_text)

        print(report_text)   # still show it live in the terminal
        print(f"\n[*] Report written to {args.output}")

    if args.csv:
        write_csv(rows, args.csv)


if __name__ == "__main__":
    main()
