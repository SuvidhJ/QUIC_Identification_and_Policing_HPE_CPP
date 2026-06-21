import pandas as pd

QUIC_FILE = "/Users/shubham_kumar/Downloads/QUIC_DET/quic_dataset.csv"
NON_QUIC_FILE = "/Users/shubham_kumar/Downloads/QUIC_DET/non_quic_dataset.csv"

# Load datasets
quic_df = pd.read_csv(QUIC_FILE, low_memory=False)
non_quic_df = pd.read_csv(NON_QUIC_FILE, low_memory=False)

# Remove frame.number if present
quic_df.drop(columns=["frame.number"], errors="ignore", inplace=True)
non_quic_df.drop(columns=["frame.number"], errors="ignore", inplace=True)

# Verify columns match
quic_cols = set(quic_df.columns)
non_quic_cols = set(non_quic_df.columns)

quic_only = quic_cols - non_quic_cols
non_quic_only = non_quic_cols - quic_cols

print("\nQUIC columns:")
print(sorted(quic_cols))

print("\nNON-QUIC columns:")
print(sorted(non_quic_cols))

if len(quic_only) == 0 and len(non_quic_only) == 0:

    print("\n✅ Schemas match")

    combined_df = pd.concat(
        [quic_df, non_quic_df],
        ignore_index=True
    )

    combined_df.to_csv(
        "/Users/shubham_kumar/Downloads/QUIC_DET/final_dataset_test2.0.csv",
        index=False
    )

    print(f"Combined rows: {len(combined_df)}")

else:

    print("\n❌ Schema mismatch detected.")

    print("\nColumns only in QUIC:")
    print(sorted(quic_only))

    print("\nColumns only in NON-QUIC:")
    print(sorted(non_quic_only))