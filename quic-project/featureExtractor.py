from nfstream import NFStreamer
import pandas as pd
import os

def extract_features(folder_path, target_label):
    data_list = []
    for file in os.listdir(folder_path):
        if file.endswith(".pcapng") or file.endswith(".pcap"):
            file_path = os.path.join(folder_path, file)
            print(f"Processing: {file_path}")

            # n_dissection=True enables the Deep Packet Inspection (DPI) engine
            streamer = NFStreamer(source=file_path, statistical_analysis=True, n_dissections=True)

            for flow in streamer:
                # We only care about UDP traffic on Port 443
                if flow.protocol == 17 and (flow.dst_port == 443 or flow.src_port == 443):
                    
                    # GOAL 1: Differentiate Generic UDP vs QUIC
                    # Check if nDPI identifies the application as QUIC or a Google service
                    app_name = flow.application_name.lower()
                    if "quic" in app_name or "google" in app_name or "youtube" in app_name:
                        final_label = target_label  # 'Streaming' or 'Web'
                    else:
                        final_label = "Generic_UDP" # It's just UDP on port 443
                    
                    features = {
                        'label': final_label,
                        'detected_protocol': flow.application_name,
                        'filesource': file,
                        'bidirectional_packets': flow.bidirectional_packets,
                        'bidirectional_bytes': flow.bidirectional_bytes,
                        'bidirectional_duration_ms': flow.bidirectional_duration_ms,
                        'bidirectional_mean_ps': flow.bidirectional_mean_ps,
                        'bidirectional_stddev_ps': flow.bidirectional_stddev_ps,
                        'bidirectional_iat_mean': flow.bidirectional_mean_piat_ms,
                        'bidirectional_iat_std': flow.bidirectional_stddev_piat_ms,
                        'src2dst_bytes': flow.src2dst_bytes,
                        'dst2src_bytes': flow.dst2src_bytes
                    }

                    data_list.append(features)

    return data_list

# Make sure your folder paths are correct
print("Starting Feature Extraction...")
streaming_data = extract_features('dataset/Streaming', 'Streaming')
web_data = extract_features('dataset/Web', 'Web')
generic_data = extract_features('dataset/Generic_UDP', 'Generic_UDP')

# Combine all data
df = pd.DataFrame(streaming_data + web_data + generic_data)

# Save to CSV
df.to_csv('quic_dataset.csv', index=False)
print("\n" + "="*40)
print("SUCCESS: quic_dataset.csv has been created!")
print(f"Total flows captured: {len(df)}")
print("Check the 'detected_protocol' column in your CSV to see the Generic UDP vs QUIC split.")
print("="*40)

print("\n" + "="*30)
print("FINAL DATASET SUMMARY:")
print(df['label'].value_counts())
print("="*30)