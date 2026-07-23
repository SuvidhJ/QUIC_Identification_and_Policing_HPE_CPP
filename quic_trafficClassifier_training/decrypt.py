# decrypt.py
#
# Network traffic labeler — groups QUIC flows by Connection ID (primary)
# or full 5-tuple (fallback for zero-length CID flows), then labels each
# flow as video / audio / web / data using HTTP/3 content-type headers
# (primary) or TLS SNI hostnames (fallback).

# Output: one CSV per pcap, one row per unique flow, with columns:
#   flow_key, ip_src, ip_dst, port_src, port_dst, proto, cid, label

import subprocess
import os
import glob
import csv
from collections import defaultdict, Counter

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
RAW_DIR     = "raw2"
DECRYPTED_DIR = "decrypted"

# ---------------------------------------------------------------------------
# Content-type prefix  →  label
# Checked in order; first match wins.
# ---------------------------------------------------------------------------
CONTENT_TYPE_MAP = [
    # video
    ("video/",                           "video"),
    ("application/vnd.yt-ump",           "video"),
    ("application/dash+xml",             "video"),
    ("application/vnd.apple.mpegurl",    "video"),
    ("audio/mpegurl",                    "video"),
    ("video/mp2t",                       "video"),
    ("video/iso.segment",                "video"),
    # audio
    ("audio/",                           "audio"),
    # web assets
    ("text/html",                        "web"),
    ("text/css",                         "web"),
    ("text/javascript",                  "web"),
    ("text/plain",                       "web"),
    ("application/javascript",           "web"),
    ("application/json",                 "web"),
    ("image/",                           "web"),
    ("font/",                            "web"),
    ("application/wasm",                 "web"),
    ("application/manifest+json",        "web"),
    ("application/xhtml+xml",            "web"),
    ("application/xml",                  "web"),
    ("text/xml",                         "web"),
    # data / signaling
    ("application/x-protobuf",           "data"),
    ("application/protobuf",             "data"),
    ("application/grpc",                 "data"),
    ("application/x-www-form-urlencoded","data"),
    ("application/octet-stream",         "data"),
    ("binary/octet-stream",              "data"),
    ("multipart/related",                "data"),
    ("multipart/form-data",              "data"),
    ("text/event-stream",                "data"),
]

# ---------------------------------------------------------------------------
# SNI hostname substring  →  label
# Used only when content-type labeling produces nothing for a flow.
# ---------------------------------------------------------------------------
SNI_MAP = [
    ("googlevideo.com",         "video"),
    ("yt3.ggpht.com",           "web"),
    ("youtu.be",                "web"),
    ("youtube.com",             "web"),
    ("scdn.co",                 "audio"),
    ("spotifycdn.com",          "audio"),
    ("audio-ak",                "audio"),
    ("video-ak",                "video"),
    ("spotify.com",             "data"),
    ("twitchsvc.net",           "video"),
    ("twitch.tv",               "video"),
    ("soundcloud.com",          "audio"),
    ("sndcdn.com",              "audio"),
    ("akamaized.net",           "audio"),
    ("meet.google.com",         "data"),
    ("drive.google.com",        "data"),
    ("docs.google.com",         "web"),
    ("storage.googleapis.com",  "data"),
]


# ===========================================================================
# SECTION 1 — Label helpers
# ===========================================================================

def get_label_from_content_type(content_type: str) -> str | None:
    """
    Walk CONTENT_TYPE_MAP and return the first matching label.
    Returns None if nothing matches — caller decides what to do.
    """
    ct = content_type.lower().strip()
    for prefix, label in CONTENT_TYPE_MAP:
        if ct.startswith(prefix):
            return label
    return None


def get_label_from_sni(sni: str) -> str | None:
    """
    Walk SNI_MAP and return the first matching label.
    Returns None if the hostname isn't in the map.
    """
    sni = sni.lower().strip()
    for pattern, label in SNI_MAP:
        if pattern in sni:
            return label
    return None


# ===========================================================================
# SECTION 2 — Flow key helpers
# ===========================================================================

def make_cid_key(cid: str) -> str:
    """
    Build a flow key from a QUIC Destination Connection ID alone.

    Why just the CID?
      A QUIC connection ID is globally unique for the lifetime of the
      connection. Two packets with the same DCID belong to the same
      connection, regardless of which IP or port they arrive on.
      That is the whole point of CIDs — they survive IP migration.

    Returns a plain string like:  "cid:a1b2c3d4e5f60708"
    """
    return f"cid:{cid.strip().lower()}"


def make_5tuple_key(src_ip: str, dst_ip: str,
                    src_port: str, dst_port: str,
                    proto: str) -> str:
    """
    Build a flow key from the full 5-tuple when no usable CID is present.

    Why direction-agnostic (sorted)?
      The same conversation produces packets in both directions.
      Packet A→B has src=A,dst=B and packet B→A has src=B,dst=A.
      Sorting the (ip,port) pairs ensures both directions hash to the
      same key so we don't create two rows for one flow.

    Why include ports?
      Your browser opens many parallel connections to the same server IP.
      Without ports, all of them collapse into one row. Each distinct
      (src_port, dst_port) pair represents a separate OS socket and
      therefore a separate QUIC connection.

    Why include protocol?
      Rare in practice for port 443, but TCP/443 and UDP/443 (QUIC) to
      the same server should not be merged into one flow.

    Returns a string like:
      "5t:192.168.1.5:54231-142.250.80.14:443/UDP"
    """
    # Sort the two (ip, port) endpoint strings so direction doesn't matter
    ep1 = f"{src_ip.strip()}:{src_port.strip()}"
    ep2 = f"{dst_ip.strip()}:{dst_port.strip()}"
    a, b = sorted([ep1, ep2])
    return f"5t:{a}-{b}/{proto.strip().upper()}"


def is_zero_length_cid(cid: str) -> bool:
    """
    tshark renders a zero-length QUIC CID as an empty string or whitespace.
    When the server negotiated CID length = 0, there is no CID on the wire,
    so we must fall back to the 5-tuple.
    """
    return cid.strip() == ""


# ===========================================================================
# SECTION 3 — tshark pass 1: content-type labels via decryption
# ===========================================================================

def extract_content_type_labels(pcap_path: str, keys_file: str) -> dict:
    """
    Ask tshark to decrypt the capture using the TLS keylog file and pull
    HTTP/3 content-type headers out of the decrypted payload.

    Fields extracted per packet:
      ip.src         — source IP
      ip.dst         — destination IP
      udp.srcport    — source UDP port  (QUIC always runs over UDP)
      udp.dstport    — destination UDP port
      ip.proto       — IP protocol number (17 = UDP)
      quic.dcid      — Destination Connection ID from the QUIC packet header
      http3.headers.content_type — decrypted HTTP/3 response header

    Why quic.dcid and not quic.scid?
      The DCID is what the *receiver* uses to look up the connection in its
      table. It's present in every single QUIC packet. The SCID only appears
      in Long Header packets (handshake phase). So DCID is the right field
      to track a flow end-to-end.

    Returns:
      dict mapping  flow_key → list of label strings
      Also returns a side-dict of flow_key → flow metadata (ips, ports, cid)
      so we can reconstruct readable CSV rows later.
    """
    cmd = [
        TSHARK_PATH,
        "-r", os.path.abspath(pcap_path),
        "-o", f"tls.keylog_file:{keys_file}",
        "-Y", "quic and http3.headers.content_type",   # only packets that have this field
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "ip.proto",
        "-e", "quic.dcid",
        "-e", "http3.headers.content_type",
        "-E", "separator=\t",                 # explicit tab separator
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)

    flow_labels   = defaultdict(list)   # flow_key → [label, label, ...]
    flow_metadata = {}                  # flow_key → {ip_src, ip_dst, ...}
    seen_types    = set()

    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue

        parts = line.split("\t")
        if len(parts) != 7:
            # tshark sometimes emits fewer fields if a value is missing;
            # skip malformed lines rather than crash
            continue

        src_ip, dst_ip, src_port, dst_port, proto, cid, content_type = parts
        seen_types.add(content_type.strip())

        label = get_label_from_content_type(content_type)
        if label is None:
            continue

        # --- choose the right key ---
        if not is_zero_length_cid(cid):
            # CID is present → use it as the primary key.
            # We still record the 5-tuple in metadata for human readability.
            key = make_cid_key(cid)
        else:
            # Zero-length CID negotiated — fall back to 5-tuple.
            key = make_5tuple_key(src_ip, dst_ip, src_port, dst_port, proto)

        flow_labels[key].append(label)

        # Store metadata on first sight; subsequent packets for the same
        # flow will have the same values so overwriting is harmless.
        if key not in flow_metadata:
            flow_metadata[key] = {
                "ip_src":   src_ip.strip(),
                "ip_dst":   dst_ip.strip(),
                "port_src": src_port.strip(),
                "port_dst": dst_port.strip(),
                "proto":    proto.strip(),
                "cid":      cid.strip(),
            }

    print(f"    [debug] content-types seen: {seen_types}")
    return flow_labels, flow_metadata


# ===========================================================================
# SECTION 4 — tshark pass 2: SNI labels (no decryption needed)
# ===========================================================================

def extract_sni_labels(pcap_path: str) -> tuple[dict, dict]:
    """
    Read TLS ClientHello packets (no keylog needed) and extract the SNI.

    Why does this work without decryption?
      In TLS 1.3 over TCP the SNI sits in the ClientHello which is sent
      in plaintext before the handshake completes. tshark can parse it
      with no keys.

      In QUIC, the TLS ClientHello is carried inside a QUIC Initial packet.
      The Initial packet uses a *well-known* key derived from the QUIC
      version and the connection ID — it is not truly secret, just
      obfuscated. Wireshark/tshark knows how to derive this key and can
      expose `tls.handshake.extensions_server_name` from QUIC Initials
      without any keylog file.

    Same key selection logic as pass 1: CID if available, 5-tuple otherwise.
    """
    cmd = [
        TSHARK_PATH,
        "-r", os.path.abspath(pcap_path),
        "-Y", "quic and tls.handshake.extensions_server_name",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "ip.proto",
        "-e", "quic.dcid",
        "-e", "tls.handshake.extensions_server_name",
        "-E", "separator=\t",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)

    flow_labels   = defaultdict(list)
    flow_metadata = {}

    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue

        parts = line.split("\t")
        if len(parts) != 7:
            continue

        src_ip, dst_ip, src_port, dst_port, proto, cid, sni = parts

        label = get_label_from_sni(sni)
        if label is None:
            continue

        if not is_zero_length_cid(cid):
            key = make_cid_key(cid)
        else:
            key = make_5tuple_key(src_ip, dst_ip, src_port, dst_port, proto)

        flow_labels[key].append(label)

        if key not in flow_metadata:
            flow_metadata[key] = {
                "ip_src":   src_ip.strip(),
                "ip_dst":   dst_ip.strip(),
                "port_src": src_port.strip(),
                "port_dst": dst_port.strip(),
                "proto":    proto.strip(),
                "cid":      cid.strip(),
            }

    return flow_labels, flow_metadata


# ===========================================================================
# SECTION 5 — Merge content-type labels with SNI fallback
# ===========================================================================

def merge_labels(ct_labels:   dict, ct_meta:  dict,
                 sni_labels:  dict, sni_meta: dict) -> tuple[dict, dict]:
    """
    Combine the two label dicts into one authoritative mapping.

    Priority:
      1. Content-type majority  (decrypted, high confidence)
      2. SNI majority           (plaintext handshake, lower confidence)

    Why majority vote instead of "first seen"?
      A single QUIC connection can serve mixed content — YouTube will
      send video chunks AND JSON metadata responses on the same connection.
      Taking the majority label reflects what the connection is *primarily*
      used for rather than what it happened to send first.

    Metadata is taken from whichever pass saw the flow first (ct preferred).
    """
    all_keys = set(ct_labels.keys()) | set(sni_labels.keys())
    merged_labels = {}
    merged_meta   = {}

    for key in all_keys:
        if ct_labels.get(key):
            merged_labels[key] = Counter(ct_labels[key]).most_common(1)[0][0]
            merged_meta[key]   = ct_meta.get(key) or sni_meta.get(key, {})
        elif sni_labels.get(key):
            merged_labels[key] = Counter(sni_labels[key]).most_common(1)[0][0]
            merged_meta[key]   = sni_meta.get(key, {})

    return merged_labels, merged_meta


# ===========================================================================
# SECTION 6 — Per-file orchestration
# ===========================================================================

def decrypt_pcap(pcap_path: str, out_csv: str) -> int:
    """
    Full pipeline for a single pcap file:
      1. Locate the matching keylog file.
      2. Run pass 1 (content-type via decryption).
      3. Run pass 2 (SNI, no decryption).
      4. Merge labels.
      5. Write CSV.

    The keylog file must sit next to the pcap with the same base name
    and a _keys.log suffix, e.g.:
        raw/capture_01.pcap  →  raw/capture_01_keys.log

    Returns the number of labeled flows written.
    """
    keys_file = os.path.abspath(pcap_path.replace(".pcap", "_keys.log"))
    if not os.path.exists(keys_file):
        print(f"    [!] keys file not found: {keys_file}")
        print(f"    [!] pass 1 skipped — SNI-only labeling will proceed")
        # Don't abort; SNI pass can still run without keys
        ct_labels, ct_meta = {}, {}
    else:
        print(f"    [pass 1] content-type labeling via decryption...")
        ct_labels, ct_meta = extract_content_type_labels(pcap_path, keys_file)
        print(f"    [pass 1] {len(ct_labels)} flows labeled via content-type")

    print(f"    [pass 2] SNI labeling (no decryption)...")
    sni_labels, sni_meta = extract_sni_labels(pcap_path)
    print(f"    [pass 2] {len(sni_labels)} flows labeled via SNI")

    labels, meta = merge_labels(ct_labels, ct_meta, sni_labels, sni_meta)
    print(f"    [merged] {len(labels)} total flows labeled")

    if not labels:
        return 0

    rows = []
    for flow_key, label in labels.items():
        m = meta.get(flow_key, {})
        rows.append({
            "flow_key":  flow_key,                   # full key string for debugging
            "ip_src":    m.get("ip_src",   ""),
            "ip_dst":    m.get("ip_dst",   ""),
            "port_src":  m.get("port_src", ""),
            "port_dst":  m.get("port_dst", ""),
            "proto":     m.get("proto",    ""),
            "cid":       m.get("cid",      ""),      # empty string = zero-length CID flow
            "label":     label,
        })

    fieldnames = ["flow_key", "ip_src", "ip_dst",
                  "port_src", "port_dst", "proto", "cid", "label"]

    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)


# ===========================================================================
# SECTION 7 — Entry point
# ===========================================================================

def main():
    os.makedirs(DECRYPTED_DIR, exist_ok=True)
    pcap_files = sorted(glob.glob(os.path.join(RAW_DIR, "*.pcap")))

    if not pcap_files:
        print(f"[!] no pcap files found in {RAW_DIR}/")
        return

    print(f"[*] found {len(pcap_files)} pcap file(s)")

    for pcap_path in pcap_files:
        base    = os.path.splitext(os.path.basename(pcap_path))[0]
        out_csv = os.path.join(DECRYPTED_DIR, f"{base}_labels.csv")
        print(f"\n[*] processing: {pcap_path}")
        n = decrypt_pcap(pcap_path, out_csv)
        print(f"    -> {n} labeled flows written to {out_csv}")

    print("\n[*] all done")


if __name__ == "__main__":
    main()