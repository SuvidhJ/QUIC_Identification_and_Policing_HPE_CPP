# decrypt.py
import subprocess
import os
import glob
import csv
from collections import defaultdict, Counter

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
RAW_DIR = "raw"
DECRYPTED_DIR = "decrypted"

CONTENT_TYPE_MAP = [
    # video
    ("video/",                          "video"),
    ("application/vnd.yt-ump",          "video"),
    ("application/dash+xml",            "video"),
    ("application/vnd.apple.mpegurl",   "video"),
    ("audio/mpegurl",                   "video"),
    ("video/mp2t",                      "video"),
    ("video/iso.segment",               "video"),
    # audio
    ("audio/",                          "audio"),
    # web assets
    ("text/html",                       "web"),
    ("text/css",                        "web"),
    ("text/javascript",                 "web"),
    ("text/plain",                      "web"),
    ("application/javascript",          "web"),
    ("application/json",                "web"),
    ("image/",                          "web"),
    ("font/",                           "web"),
    ("application/wasm",                "web"),
    ("application/manifest+json",       "web"),
    ("application/xhtml+xml",           "web"),
    ("application/xml",                 "web"),
    ("text/xml",                        "web"),
    # data / signaling
    ("application/x-protobuf",          "data"),
    ("application/protobuf",            "data"),
    ("application/grpc",                "data"),
    ("application/x-www-form-urlencoded","data"),
    ("application/octet-stream",        "data"),
    ("binary/octet-stream",             "data"),
    ("multipart/related",               "data"),
    ("multipart/form-data",             "data"),
    ("text/event-stream",               "data"),
]

# SNI hostname patterns -> label (fallback when content-type labeling fails)
SNI_MAP = [
    ("googlevideo.com",         "video"),   # YouTube media CDN
    ("yt3.ggpht.com",           "video"),   # YouTube thumbnails/art (treat as web)
    ("youtu.be",                "web"),
    ("youtube.com",             "web"),
    ("googlevideo.com",         "video"),
    ("scdn.co",                 "audio"),   # Spotify audio CDN (audio-ak-spotify-com.akamaized.net etc)
    ("spotifycdn.com",          "audio"),   # Spotify CDN
    ("audio-ak",                "audio"),   # Spotify Akamai audio edge
    ("video-ak",                "video"),   # Spotify Canvas video
    ("spotify.com",             "data"),    # Spotify API/signaling
    ("twitchsvc.net",           "video"),   # Twitch media
    ("twitch.tv",               "video"),
    ("soundcloud.com",          "audio"),
    ("sndcdn.com",              "audio"),   # SoundCloud CDN
    ("akamaized.net",           "audio"),   # generic Akamai (mostly audio for our captures)
    ("meet.google.com",         "data"),
    ("drive.google.com",        "data"),
    ("docs.google.com",         "web"),
    ("storage.googleapis.com",  "data"),
]

def get_label_from_content_type(content_type):
    ct = content_type.lower().strip()
    for prefix, label in CONTENT_TYPE_MAP:
        if ct.startswith(prefix):
            return label
    return None

def get_label_from_sni(sni):
    sni = sni.lower().strip()
    for pattern, label in SNI_MAP:
        if pattern in sni:
            return label
    return None

def extract_content_type_labels(pcap_path, keys_file):
    """Pass 1: label flows via decrypted HTTP/3 content-type headers."""
    cmd = [
        TSHARK_PATH,
        "-r", os.path.abspath(pcap_path),
        "-o", f"tls.keylog_file:{keys_file}",
        "-Y", "http3.headers.content_type",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "http3.headers.content_type",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # ip_pair -> list of labels seen
    pair_labels = defaultdict(list)
    seen_types = set()

    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        src_ip, dst_ip, content_type = parts
        seen_types.add(content_type.strip())
        label = get_label_from_content_type(content_type)
        if label is None:
            continue
        # store as canonical (sorted) pair so direction doesn't matter
        key = tuple(sorted([src_ip.strip(), dst_ip.strip()]))
        pair_labels[key].append(label)

    print(f"    [debug] content-types seen: {seen_types}")
    return pair_labels

def extract_sni_labels(pcap_path):
    """Pass 2: label flows via TLS SNI (no decryption needed)."""
    cmd = [
        TSHARK_PATH,
        "-r", os.path.abspath(pcap_path),
        "-Y", "tls.handshake.extensions_server_name",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tls.handshake.extensions_server_name",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)

    pair_labels = defaultdict(list)

    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        src_ip, dst_ip, sni = parts
        label = get_label_from_sni(sni)
        if label is None:
            continue
        key = tuple(sorted([src_ip.strip(), dst_ip.strip()]))
        pair_labels[key].append(label)

    return pair_labels

def merge_labels(ct_labels, sni_labels):
    """
    Merge content-type labels (primary) with SNI labels (fallback).
    For each IP pair, content-type majority wins. If no content-type
    label exists for a pair, fall back to SNI majority.
    """
    all_keys = set(ct_labels.keys()) | set(sni_labels.keys())
    merged = {}
    for key in all_keys:
        if key in ct_labels and ct_labels[key]:
            # content-type label available — take majority
            merged[key] = Counter(ct_labels[key]).most_common(1)[0][0]
        elif key in sni_labels and sni_labels[key]:
            # fallback to SNI
            merged[key] = Counter(sni_labels[key]).most_common(1)[0][0]
    return merged

def decrypt_pcap(pcap_path, out_csv):
    keys_file = os.path.abspath(pcap_path.replace(".pcap", "_keys.log"))
    if not os.path.exists(keys_file):
        print(f"    [!] keys file not found: {keys_file}")
        return 0

    print(f"    [pass 1] content-type labeling...")
    ct_labels = extract_content_type_labels(pcap_path, keys_file)
    print(f"    [pass 1] {len(ct_labels)} ip pairs labeled via content-type")

    print(f"    [pass 2] SNI labeling...")
    sni_labels = extract_sni_labels(pcap_path)
    print(f"    [pass 2] {len(sni_labels)} ip pairs labeled via SNI")

    labels = merge_labels(ct_labels, sni_labels)
    print(f"    [merged] {len(labels)} total ip pairs labeled")

    if not labels:
        return 0

    rows = []
    for (ip_a, ip_b), label in labels.items():
        rows.append({
            "ip_a":  ip_a,
            "ip_b":  ip_b,
            "label": label,
        })

    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip_a", "ip_b", "label"])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def main():
    os.makedirs(DECRYPTED_DIR, exist_ok=True)
    pcap_files = sorted(glob.glob(os.path.join(RAW_DIR, "*.pcap")))

    if not pcap_files:
        print(f"[!] no pcap files found in {RAW_DIR}/")
        return

    print(f"[*] found {len(pcap_files)} pcap files")
    for pcap_path in pcap_files:
        base    = os.path.splitext(os.path.basename(pcap_path))[0]
        out_csv = os.path.join(DECRYPTED_DIR, f"{base}_labels.csv")
        print(f"[*] processing {pcap_path}...")
        n = decrypt_pcap(pcap_path, out_csv)
        print(f"    -> {n} labeled ip pairs -> {out_csv}")

    print("[*] all done")

if __name__ == "__main__":
    main()