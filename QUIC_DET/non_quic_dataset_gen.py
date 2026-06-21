import pandas as pd
import subprocess
import os

TSHARK_PATH = "/Applications/Wireshark.app/Contents/MacOS/tshark"

PCAPS = [
    "/Users/shubham_kumar/Downloads/QUIC_DET/non_quic1.pcapng"
    
]

OUTPUT_CSV = "/Users/shubham_kumar/Downloads/QUIC_DET/non_quic_dataset.csv"

FIELDS = [
    "frame.time_epoch",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
    "ip.proto",
    "ipv6.nxt",
    "quic.packet_length",
    "quic.packet_number",
    "quic.packet_number_length",
    "quic.version",
    "quic.header_form",
    "quic.long.packet_type",
    "quic.dcid",
    "quic.scid",
    "tcp.srcport",
    "tcp.dstport",
    "tls.handshake.extensions_server_name",
    "quic.fixed_bit",
    "http3.frame_streamid",
    "http3.headers.method",
    "http3.headers.authority",

    "_ws.col.protocol",

    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst"
]

all_dfs = []

for pcap in PCAPS:

    print(f"Processing {os.path.basename(pcap)}")

    cmd = [TSHARK_PATH, "-r", pcap]

    for field in FIELDS:
        cmd.extend(["-e", field])

    cmd.extend([
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f"
    ])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(result.stderr)
        continue

    temp_csv = "non_quic.csv"

    with open(temp_csv, "w") as f:
        f.write(result.stdout)

    df = pd.read_csv(
        temp_csv,
        dtype=str,
        keep_default_na=False
    )
    PROTO_MAP = {
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
        "33": "DCCP",
        "132": "SCTP"
    }

    df["transport_proto_num"] = ""

    df.loc[df["ip.proto"] != "", "transport_proto_num"] = df["ip.proto"]

    df.loc[
        (df["transport_proto_num"] == "") &
        (df["ipv6.nxt"] != ""),
        "transport_proto_num"
    ] = df["ipv6.nxt"]

    df["transport_protocol"] = (
        df["transport_proto_num"]
        .map(PROTO_MAP)
        .fillna("OTHER")
    )
    # print(df.columns.tolist())
    # exit()
    # Merge IPv4 and IPv6 columns (prefer IPv6 if present)
    if "ipv6.src" in df.columns and "ip.src" in df.columns:
        df["ip_src"] = df["ipv6.src"].combine_first(df["ip.src"])
    elif "ipv6.src" in df.columns:
        df["ip_src"] = df["ipv6.src"]
    elif "ip.src" in df.columns:
        df["ip_src"] = df["ip.src"]

    if "ipv6.dst" in df.columns and "ip.dst" in df.columns:
        df["ip_dst"] = df["ipv6.dst"].combine_first(df["ip.dst"])
    elif "ipv6.dst" in df.columns:
        df["ip_dst"] = df["ipv6.dst"]
    elif "ip.dst" in df.columns:
        df["ip_dst"] = df["ip.dst"]

    # Drop original IP columns
    df.drop(
        columns=["ip.src", "ipv6.src", "ip.dst", "ipv6.dst"],
        errors="ignore",
        inplace=True
    )
    df = df[
    df["transport_protocol"].isin(
            ["UDP", "TCP","SCTP","DCCP"]
        )
    ]
    if "quic.fixed_bit" not in df.columns:
        df["quic.fixed_bit"] = 0
    df["quic.fixed_bit"] = (
        df["quic.fixed_bit"]
        .astype(str)
        .str.lower()
        .map({
            "true": 1,
            "false": 0,
            "1": 1,
            "0": 0
        })
        .fillna(0)
    )
    df["label"] = "NON-QUIC"

    df["srcport"] = (
        pd.to_numeric(df["udp.srcport"], errors="coerce")
        .fillna(pd.to_numeric(df["tcp.srcport"], errors="coerce"))
    )

    df["dstport"] = (
        pd.to_numeric(df["udp.dstport"], errors="coerce")
        .fillna(pd.to_numeric(df["tcp.dstport"], errors="coerce"))
    )
    df = df[
        [
            "frame.time_epoch",

            "srcport",
            "dstport",

            "frame.len",

            "quic.packet_length",
            "quic.packet_number",
            "quic.packet_number_length",
            "quic.version",
            "quic.header_form",
            "quic.long.packet_type",
            "quic.dcid",
            "quic.scid",

            "tls.handshake.extensions_server_name",
            "http3.frame_streamid",
            "http3.headers.method",
            "http3.headers.authority",

            "ip_src",
            "ip_dst",

            "quic.fixed_bit",

            "transport_protocol",
            "label"
        ]
    ]

    all_dfs.append(df)

if not all_dfs:
    raise RuntimeError("No packets extracted")

final_df = pd.concat(
    all_dfs,
    ignore_index=True
)

final_df.to_csv(
    OUTPUT_CSV,
    index=False
)

print(f"Saved: {OUTPUT_CSV}")
print(f"Packets: {len(final_df)}")
print(f"Columns: {len(final_df.columns)}")