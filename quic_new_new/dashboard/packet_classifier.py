"""
Real-time per-packet QUIC/NON-QUIC classifier.
- No scapy, no tshark, no external libraries.
- Uses raw AF_PACKET socket for live capture on a given interface.
- Per-packet output: QUIC | NON_QUIC | QUIC_PROBABLE | PENDING
- Buffers up to WINDOW_SIZE packets per new flow, then classifies
  using QUICDetector; all future packets on that flow use cached label.

Usage:
    sudo python3 packet_classifier.py --iface eth0 --model-dir models/
    sudo python3 packet_classifier.py --iface eth0 --model-dir models/ --verbose
"""

import socket
import struct
import time
import argparse
import os
import sys
from collections import defaultdict

# ── QUICDetector is expected to be importable from the same directory ──────────
# Paste or symlink the detector module alongside this file.
from quic_detector import QUICDetector   # adjust import name if needed

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
WINDOW_SIZE      = 5          # packets to buffer before classifying a new flow
FLOW_TTL_SECONDS = 180        # evict cached labels after this idle time
ETH_P_ALL        = 0x0003     # capture everything
ETH_P_IP         = 0x0800
IPPROTO_UDP      = 17
IPPROTO_TCP      = 6

# QUIC long-header packet type nibbles (bits 4-5 of first byte, long header)
QUIC_LONG_TYPE = {
    0x00: 'initial',
    0x01: 'zero_rtt',
    0x02: 'handshake',
    0x03: 'retry',
}

# Known valid QUIC versions (big-endian 4-byte)
KNOWN_QUIC_VERSIONS = {
    0x00000001,   # QUIC v1  (RFC 9000)
    0x6b3343cf,   # draft-29
    0xff00001d,   # draft-29 alt
    0xff00001e,   # draft-30
    0xff00001f,   # draft-31
    0x51303530,   # Google QUIC Q050
    0x54303530,   # Google QUIC T050
    0x00000000,   # Version Negotiation sentinel
}

# ─────────────────────────────────────────────────────────────────────────────
# Layer parsers  (pure stdlib – struct only)
# ─────────────────────────────────────────────────────────────────────────────

def parse_ethernet(raw: bytes):
    """Return (ethertype, payload) or None on short frame."""
    if len(raw) < 14:
        return None
    ethertype = struct.unpack_from('!H', raw, 12)[0]
    # Skip 802.1Q VLAN tag
    if ethertype == 0x8100 and len(raw) >= 18:
        ethertype = struct.unpack_from('!H', raw, 16)[0]
        return ethertype, raw[18:]
    return ethertype, raw[14:]


def parse_ipv4(payload: bytes):
    """
    Return dict with src_ip, dst_ip, protocol, ip_payload.
    Returns None on malformed packet.
    """
    if len(payload) < 20:
        return None
    ihl = (payload[0] & 0x0F) * 4
    if len(payload) < ihl:
        return None
    proto = payload[9]
    src_ip = socket.inet_ntoa(payload[12:16])
    dst_ip = socket.inet_ntoa(payload[16:20])
    return {
        'src_ip':     src_ip,
        'dst_ip':     dst_ip,
        'protocol':   proto,
        'ip_payload': payload[ihl:]
    }


def parse_udp(ip_payload: bytes):
    """Return (src_port, dst_port, udp_payload) or None."""
    if len(ip_payload) < 8:
        return None
    src_port, dst_port = struct.unpack_from('!HH', ip_payload)
    return src_port, dst_port, ip_payload[8:]


def parse_tcp(ip_payload: bytes):
    """Return (src_port, dst_port) or None (we don't need TCP payload here)."""
    if len(ip_payload) < 20:
        return None
    src_port, dst_port = struct.unpack_from('!HH', ip_payload)
    return src_port, dst_port


# ─────────────────────────────────────────────────────────────────────────────
# QUIC header parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_quic_packet(udp_payload: bytes) -> dict:
    """
    Parse a single UDP payload as a potential QUIC packet.
    Returns a feature dict.  All values default to 0 / empty on failure.
    """
    feat = {
        'is_long_header':   0,
        'fixed_bit':        0,
        'version':          None,
        'valid_version':    0,
        'packet_type':      None,   # 'initial','zero_rtt','handshake','retry'
        'dcid':             None,
        'scid':             None,
    }

    if not udp_payload:
        return feat

    first_byte = udp_payload[0]

    # Fixed bit (bit 6, i.e. 0x40) must be 1 for QUIC
    feat['fixed_bit'] = 1 if (first_byte & 0x40) else 0

    # Long header: bit 7 set
    is_long = bool(first_byte & 0x80)
    feat['is_long_header'] = int(is_long)

    if is_long:
        # Long header layout:
        # 1B flags | 4B version | 1B dcid_len | dcid | 1B scid_len | scid
        if len(udp_payload) < 7:
            return feat

        version = struct.unpack_from('!I', udp_payload, 1)[0]
        feat['version'] = version
        feat['valid_version'] = int(version in KNOWN_QUIC_VERSIONS)

        # Packet type (bits 4-5 of first byte, masked)
        pkt_type_nibble = (first_byte & 0x30) >> 4
        feat['packet_type'] = QUIC_LONG_TYPE.get(pkt_type_nibble)

        offset = 5
        if offset >= len(udp_payload):
            return feat

        dcid_len = udp_payload[offset]
        offset += 1
        if offset + dcid_len > len(udp_payload):
            return feat
        feat['dcid'] = udp_payload[offset: offset + dcid_len].hex()
        offset += dcid_len

        if offset >= len(udp_payload):
            return feat
        scid_len = udp_payload[offset]
        offset += 1
        if offset + scid_len <= len(udp_payload):
            feat['scid'] = udp_payload[offset: offset + scid_len].hex()

    else:
        # Short header: 1B flags | dcid (length unknown without context, skip)
        pass

    return feat


# ─────────────────────────────────────────────────────────────────────────────
# Flow-level feature aggregation over the packet window
# ─────────────────────────────────────────────────────────────────────────────

def aggregate_flow_features(five_tuple: tuple, pkt_features: list) -> dict:
    """
    Given a list of per-packet QUIC feature dicts (length == WINDOW_SIZE),
    produce the flow-level feature dict expected by QUICDetector.
    """
    src_ip, dst_ip, src_port, dst_port, proto_str = five_tuple
    n = len(pkt_features)

    long_header_count   = sum(p['is_long_header']  for p in pkt_features)
    fixed_bit_count     = sum(p['fixed_bit']        for p in pkt_features)
    valid_version_count = sum(p['valid_version']    for p in pkt_features)

    versions = [p['version'] for p in pkt_features if p['version'] is not None]
    unique_versions = len(set(versions))

    type_counts = defaultdict(int)
    for p in pkt_features:
        if p['packet_type']:
            type_counts[p['packet_type']] += 1

    dcids = list({p['dcid'] for p in pkt_features if p['dcid']})
    scids = list({p['scid'] for p in pkt_features if p['scid']})

    flow = {
        # 5-tuple
        'src_ip':              src_ip,
        'dst_ip':              dst_ip,
        'src_port':            src_port,
        'dst_port':            dst_port,
        'transport_protocol':  proto_str,

        # Ratios
        'long_header_ratio':           long_header_count   / n,
        'fixed_bit_ratio':             fixed_bit_count     / n,
        'valid_version_ratio':         valid_version_count / n,
        'unique_versions':             unique_versions,

        # Handshake packet type ratios
        'initial_packet_ratio':            type_counts['initial']   / n,
        'handshake_packet_ratio':          type_counts['handshake'] / n,
        'retry_packet_ratio':              type_counts['retry']     / n,
        'zero_rtt_ratio':                  type_counts['zero_rtt']  / n,
        'version_negotiation_ratio':       0.0,   # hard to detect without full state

        # CID lists (QUICDetector._get_cids looks for 'dcids'/'scids')
        'dcids': dcids,
        'scids': scids,

        # Packet-count hint (some ML models use this)
        'packet_count': n,
    }
    return flow


# ─────────────────────────────────────────────────────────────────────────────
# Per-packet classifier
# ─────────────────────────────────────────────────────────────────────────────

class PerPacketClassifier:
    def __init__(self, model_dir: str, verbose: bool = False):
        self.verbose   = verbose
        self.detector  = QUICDetector(model_dir=model_dir)

        # 5-tuple → {'label', 'confidence', 'tier', 'reason', 'last_seen'}
        self.flow_cache: dict = {}

        # 5-tuple → list of per-packet QUIC feature dicts (buffer)
        self.pending:    dict = defaultdict(list)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _normalize_tuple(self, src_ip, dst_ip, src_port, dst_port, proto) -> tuple:
        """Always sort so fwd and rev map to the same key."""
        proto_str = 'UDP' if proto == IPPROTO_UDP else ('TCP' if proto == IPPROTO_TCP else str(proto))
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        lo, hi = (a, b) if a <= b else (b, a)
        return (lo[0], hi[0], lo[1], hi[1], proto_str)

    def _evict_stale(self):
        now   = time.time()
        stale = [k for k, v in self.flow_cache.items()
                 if now - v['last_seen'] > FLOW_TTL_SECONDS]
        for k in stale:
            del self.flow_cache[k]
            self.pending.pop(k, None)

    def _store(self, key, label, conf, tier, reason):
        self.flow_cache[key] = {
            'label':      label,
            'confidence': conf,
            'tier':       tier,
            'reason':     reason,
            'last_seen':  time.time(),
        }

    # ── public API ────────────────────────────────────────────────────────────

    def process_packet(self, raw: bytes) -> dict:
        """
        Accept a raw Ethernet frame.
        Returns:
            {
              'label':      'QUIC' | 'NON_QUIC' | 'QUIC_PROBABLE' | 'PENDING' | 'SKIP',
              'confidence': float or None,
              'tier':       str or None,
              'reason':     str,
              'five_tuple': tuple or None,
            }
        """
        result = {'label': 'SKIP', 'confidence': None,
                  'tier': None, 'reason': 'Not IP', 'five_tuple': None}

        # ── Ethernet ─────────────────────────────────────────────────────────
        eth = parse_ethernet(raw)
        if eth is None or eth[0] != ETH_P_IP:
            return result

        ethertype, l3 = eth

        # ── IPv4 ─────────────────────────────────────────────────────────────
        ip = parse_ipv4(l3)
        if ip is None:
            result['reason'] = 'Malformed IP'
            return result

        proto = ip['protocol']
        if proto not in (IPPROTO_UDP, IPPROTO_TCP):
            result['label']  = 'NON_QUIC'
            result['confidence'] = 1.0
            result['reason'] = 'Not UDP/TCP'
            return result

        # ── Transport ────────────────────────────────────────────────────────
        udp_payload = b''
        if proto == IPPROTO_UDP:
            udp = parse_udp(ip['ip_payload'])
            if udp is None:
                result['reason'] = 'Malformed UDP'
                return result
            src_port, dst_port, udp_payload = udp
        else:
            tcp = parse_tcp(ip['ip_payload'])
            if tcp is None:
                result['reason'] = 'Malformed TCP'
                return result
            src_port, dst_port = tcp

        five_tuple = self._normalize_tuple(
            ip['src_ip'], ip['dst_ip'], src_port, dst_port, proto
        )
        result['five_tuple'] = five_tuple

        # ── Evict stale entries periodically ─────────────────────────────────
        # (cheap check: only every ~100 calls via hash trick)
        if hash(five_tuple) % 100 == 0:
            self._evict_stale()

        # ── Cache hit ────────────────────────────────────────────────────────
        if five_tuple in self.flow_cache:
            cached = self.flow_cache[five_tuple]
            cached['last_seen'] = time.time()   # refresh TTL
            result.update({
                'label':      cached['label'],
                'confidence': cached['confidence'],
                'tier':       cached['tier'],
                'reason':     cached['reason'] + ' [cached]',
            })
            return result

        # ── TCP is never QUIC ─────────────────────────────────────────────────
        if proto == IPPROTO_TCP:
            self._store(five_tuple, 'NON_QUIC', 1.0, 'Tier 1', 'TCP flow')
            result.update({'label': 'NON_QUIC', 'confidence': 1.0,
                           'tier': 'Tier 1', 'reason': 'TCP flow'})
            return result

        # ── Buffer phase: parse QUIC features for this packet ────────────────
        pkt_feat = parse_quic_packet(udp_payload)
        self.pending[five_tuple].append(pkt_feat)

        if len(self.pending[five_tuple]) < WINDOW_SIZE:
            result.update({
                'label':  'PENDING',
                'reason': f'Buffering ({len(self.pending[five_tuple])}/{WINDOW_SIZE} pkts)',
            })
            return result

        # ── Window full: classify ─────────────────────────────────────────────
        window = self.pending.pop(five_tuple)          # consume buffer

        # Build the original-direction 5-tuple dict QUICDetector expects
        # (we stored a sorted key; reconstruct with src as the smaller side)
        src_ip, dst_ip, src_port_n, dst_port_n, proto_str = five_tuple
        flow_dict = aggregate_flow_features(
            (src_ip, dst_ip, src_port_n, dst_port_n, proto_str), window
        )

        label, conf, tier, reason = self.detector.classify_flow(flow_dict)

        self._store(five_tuple, label, conf, tier, reason)

        result.update({
            'label':      label,
            'confidence': conf,
            'tier':       tier,
            'reason':     reason + ' [window classified]',
        })
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Live capture loop
# ─────────────────────────────────────────────────────────────────────────────

def capture_loop(iface: str, classifier: PerPacketClassifier):
    """Open a raw socket on *iface* and classify every packet."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(ETH_P_ALL))
    sock.bind((iface, 0))
    print(f"[*] Listening on {iface}  (Ctrl-C to stop)\n")

    pkt_count = 0
    try:
        while True:
            raw, _ = sock.recvfrom(65536)
            pkt_count += 1
            result    = classifier.process_packet(raw)

            if result['label'] == 'SKIP':
                continue   # non-IP, silently ignore

            ts = time.strftime('%H:%M:%S')
            ft = result['five_tuple']
            ft_str = (f"{ft[0]}:{ft[2]} → {ft[1]}:{ft[3]} [{ft[4]}]"
                      if ft else "?")

            conf_str = (f"  conf={result['confidence']:.3f}"
                        if result['confidence'] is not None else "")

            print(
                f"[{ts}] #{pkt_count:>6}  "
                f"{result['label']:<14} "
                f"{ft_str:<45} "
                f"{conf_str}"
                f"  tier={result['tier'] or '-'}"
                f"  {result['reason']}"
            )

    except KeyboardInterrupt:
        print(f"\n[*] Stopped. {pkt_count} packets processed.")
    finally:
        sock.close()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Real-time per-packet QUIC classifier (no external libs)')
    parser.add_argument('--iface',     required=True,
                        help='Network interface to sniff (e.g. eth0, h1-eth0)')
    parser.add_argument('--model-dir', default='models',
                        help='Directory containing best_model.pkl + metadata.json')
    parser.add_argument('--verbose',   action='store_true',
                        help='Print every packet including NON_QUIC')
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit('[!] Raw socket requires root. Run with sudo.')

    if not os.path.isdir(args.model_dir):
        sys.exit(f'[!] Model directory not found: {args.model_dir}')

    classifier = PerPacketClassifier(model_dir=args.model_dir,
                                     verbose=args.verbose)
    capture_loop(args.iface, classifier)


if __name__ == '__main__':
    main()
