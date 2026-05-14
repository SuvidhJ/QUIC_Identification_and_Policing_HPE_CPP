import pandas as pd
import os
import numpy as np

# 🔷 CONFIG
window_size = 10
step_size = 5   # 🔥 overlap (important)
csv_folder = r"C:\Users\sshub.KUMAR-S-ENVY\OneDrive\Documents\HPE CPP\TASK_WEEK4\Testing_packets"

files = {
    "yt.csv": "video",
    # "hotstar.csv": "video",
    "amazon.csv": "browsing",
    "zoom_call.csv": "voip",
    "whatsapp.csv": "chat",
    # "google_drive.csv": "download",
    "twitch.csv": "live",
    # "instagram_reels.csv": "short_video"
}

all_flows = []

for file, label in files.items():

    file_path = os.path.join(csv_folder, file)
    print(f"Processing {file_path}...")

    df = pd.read_csv(file_path)

    # Rename columns
    df.rename(columns={
        'frame.time_epoch': 'Time',
        'frame.len': 'Length'
    }, inplace=True)

    # Clean
    df['Time'] = pd.to_numeric(df['Time'], errors='coerce')
    df = df.dropna(subset=['Time'])
    df = df.sort_values(by='Time')

    # Normalize time
    df['Time'] = df['Time'] - df['Time'].min()

    max_time = df['Time'].max()

    # 🔥 Sliding window (overlapping)
    start = 0

    while start < max_time:

        end = start + window_size

        group = df[(df['Time'] >= start) & (df['Time'] < end)]

        if len(group) < 10:
            start += step_size
            continue

        sizes = group['Length']

        avg_pkt_size = sizes.mean()
        std_dev = sizes.std()
        max_pkt_size = sizes.max()
        min_pkt_size = sizes.min()
        pkt_count = len(group)

        # IAT
        iat = group['Time'].diff().dropna()
        avg_iat = iat.mean() if not iat.empty else 0
        iat_std = iat.std() if not iat.empty else 0

        duration = group['Time'].max() - group['Time'].min()
        pkt_rate = pkt_count / duration if duration > 0 else 0

        # Additional variability feature
        size_iqr = np.percentile(sizes, 75) - np.percentile(sizes, 25)

        # Burstiness
        burstiness = pkt_rate / (avg_iat + 1e-6)

        all_flows.append({
            "flow": f"{file}_{start:.1f}",
            "avg_pkt_size": avg_pkt_size,
            "std_dev": std_dev,
            "max_pkt_size": max_pkt_size,
            "min_pkt_size": min_pkt_size,
            "pkt_count": pkt_count,
            "avg_iat": avg_iat,
            "iat_std": iat_std,
            "duration": duration,
            "pkt_rate": pkt_rate,
            "size_iqr": size_iqr,
            "burstiness": burstiness,
            "label": label
        })

        start += step_size  # 🔥 overlap shift

# FINAL DATASET
final_df = pd.DataFrame(all_flows)

final_df.to_csv("dataset2.csv", index=False)

print("\n✅ Improved dataset created")
print(final_df.head())
print("Total flows:", len(final_df))