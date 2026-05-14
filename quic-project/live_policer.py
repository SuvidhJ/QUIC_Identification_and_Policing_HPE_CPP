import joblib
import pandas as pd
from nfstream import NFStreamer

# 1. Load the brain
model = joblib.load('quic_classifier.pkl')
print("--- REAL-TIME YOUTUBE CLASSIFIER ACTIVE ---")
print("Monitoring interface: enp0s1")

# 2. Sniff on the real internet interface
streamer = NFStreamer(source="lo0", statistical_analysis=True)

for flow in streamer:
    # We only care about flows with enough data to actually be a 'stream'
    if flow.bidirectional_packets > 20:
        feat_data = {
            'bidirectional_packets': flow.bidirectional_packets,
            'bidirectional_bytes': flow.bidirectional_bytes,
            'bidirectional_mean_ps': flow.bidirectional_mean_ps,
            'bidirectional_iat_std': flow.bidirectional_stddev_piat_ms,
            'src2dst_bytes': flow.src2dst_bytes,
            'dst2src_bytes': flow.dst2src_bytes
        }
        
        features = pd.DataFrame([feat_data])
        prediction = model.predict(features)[0]
        
        # Output results to the console
        print(f"[+] Protocol: {flow.application_name} | Bytes: {flow.bidirectional_bytes} | Prediction: {prediction}")