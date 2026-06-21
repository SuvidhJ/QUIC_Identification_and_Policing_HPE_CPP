import pandas as pd

df = pd.read_csv(
    "/Users/shubham_kumar/Downloads/QUIC_DET/flow_features_test.csv"
)

print(df["label"].value_counts())