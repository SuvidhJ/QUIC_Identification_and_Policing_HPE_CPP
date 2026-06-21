import pandas as pd
import numpy as np

INPUT_FILE = "/Users/shubham_kumar/Downloads/QUIC_DET/final_dataset_test2.0.csv"
OUTPUT_FILE = "/Users/shubham_kumar/Downloads/QUIC_DET/flow_features_test2.0.csv"

FLOW_TIMEOUT = 15.0

VALID_VERSIONS = {
    "0x6b3343cf",
    "0x00000001"
}

def get_flow_key(row):

    src = str(row["ip_src"]).strip()
    dst = str(row["ip_dst"]).strip()

    sport = row["srcport"]
    dport = row["dstport"]

    if pd.isna(sport) or pd.isna(dport):
        return (
            "MISSING_PORT",
            src,
            dst,
            row["transport_protocol"]
        )

    sport = int(sport)
    dport = int(dport)

    proto = str(row["transport_protocol"]).strip()

    endpoint1 = (src, sport)
    endpoint2 = (dst, dport)

    if endpoint1 <= endpoint2:
        return ("5TUPLE", endpoint1, endpoint2, proto)

    return ("5TUPLE", endpoint2, endpoint1, proto)

def build_flows(df):
    df = df.sort_values("frame.time_epoch")

    active_flows = {}
    completed_flows = []

    for _, row in df.iterrows():

        ts = float(row["frame.time_epoch"])
        key = get_flow_key(row)

        expired = []

        for flow_key, flow in active_flows.items():
            if ts - flow["last_seen"] > FLOW_TIMEOUT:
                completed_flows.append(flow)
                expired.append(flow_key)

        for e in expired:
            del active_flows[e]

        if key not in active_flows:
            active_flows[key] = {
                "packets": [],
                "first_seen": ts,
                "last_seen": ts
            }

        active_flows[key]["packets"].append(row)
        active_flows[key]["last_seen"] = ts

    completed_flows.extend(active_flows.values())

    return completed_flows


def compute_flow_features(flow):

    packets = flow["packets"]

    times = np.array(
        [float(p["frame.time_epoch"]) for p in packets]
    )

    sizes = np.array(
        [float(p["frame.len"]) for p in packets]
    )

    duration = max(times) - min(times)

    if duration <= 0:
        duration = 1e-6

    packet_count = len(packets)
    total_bytes = sizes.sum()

    long_headers = 0
    short_headers = 0

    fixed_bits = []

    valid_versions = 0
    versions_seen = set()

    initial_count = 0
    handshake_count = 0
    retry_count = 0
    zero_rtt_count = 0
    vn_count = 0

    dcid = None
    scid = None

    for p in packets:

        hf = p.get("quic.header_form")

        if pd.notna(hf):

            hf = str(hf).split(",")[0].strip()

            try:
                hf = int(hf)

                if hf == 1:
                    long_headers += 1
                else:
                    short_headers += 1

            except ValueError:
                pass
        fb = p.get("quic.fixed_bit")
        if pd.notna(fb):
            fixed_bits.append(int(fb))

        version = str(p.get("quic.version", "")).strip()

        if version and version.lower() != "nan":

            versions_seen.add(version)

            if version in VALID_VERSIONS:
                valid_versions += 1

            if version == "0x00000000":
                vn_count += 1

        pkt_type = p.get("quic.long.packet_type")

        if pd.notna(pkt_type):

            try:
                pkt_type = int(str(pkt_type).split(",")[0].strip())

                if pkt_type == 0:
                    initial_count += 1

                elif pkt_type == 1:
                    zero_rtt_count += 1

                elif pkt_type == 2:
                    handshake_count += 1

                elif pkt_type == 3:
                    retry_count += 1

            except ValueError:
                pass

        if dcid is None:
            val = p.get("quic.dcid")
            if pd.notna(val):
                dcid = str(val)

        if scid is None:
            val = p.get("quic.scid")
            if pd.notna(val):
                scid = str(val)

    iats = np.diff(np.sort(times))

    if len(iats) == 0:
        avg_iat = 0
        std_iat = 0
    else:
        avg_iat = float(np.mean(iats))
        std_iat = float(np.std(iats))

    first_packet = packets[0]
    flow_label = first_packet.get("label", "")
    return {
        "transport_protocol":
            first_packet["transport_protocol"],

        "long_header_ratio":
            long_headers / packet_count,
        "short_header_ratio":
            short_headers / packet_count,
        "fixed_bit_ratio":
            np.mean(fixed_bits) if fixed_bits else 0,

        "valid_version_ratio":
            valid_versions / packet_count,

        "unique_versions":
            len(versions_seen),

        "initial_packet_ratio":
            initial_count / packet_count,

        "handshake_packet_ratio":
            handshake_count / packet_count,

        "retry_packet_ratio":
            retry_count / packet_count,

        "zero_rtt_ratio":
            zero_rtt_count / packet_count,

        "version_negotiation_ratio":
            vn_count / packet_count,

        "packet_count":
            packet_count,

        "total_bytes":
            total_bytes,

        "duration":
            duration,

        "bytes_per_sec":
            total_bytes / duration,

        "packets_per_sec":
            packet_count / duration,

        "avg_pkt_size":
            float(np.mean(sizes)),

        "std_pkt_size":
            float(np.std(sizes)),

        "avg_iat":
            avg_iat,

        "std_iat":
            std_iat,

        "dcid":
            dcid,

        "scid":
            scid,

        "src_ip":
            first_packet["ip_src"],

        "dst_ip":
            first_packet["ip_dst"],

        "src_port":
            first_packet["srcport"],

        "dst_port":
            first_packet["dstport"],
        "label":
            flow_label,
    }


def main():

    df = pd.read_csv(INPUT_FILE)

    flows = build_flows(df)

    features = []

    for flow in flows:
        features.append(
            compute_flow_features(flow)
        )

    out_df = pd.DataFrame(features)
    print("\nQUIC flow statistics")
    print(
        out_df[out_df["label"] == "QUIC"][
            ["packet_count",
            "long_header_ratio",
            "short_header_ratio",
            "unique_versions"]
        ].describe()
    )
    print(
        out_df[out_df["label"] == "QUIC"][
            ["packet_count"]
        ].value_counts().head(20)
    )
    out_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(f"Generated {len(out_df)} flows")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()