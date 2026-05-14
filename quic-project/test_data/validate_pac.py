import joblib
import pandas as pd
from nfstream import NFStreamer

# Load the model
model = joblib.load('quic_classifier.pkl')

def test_pcap(file_path):
    print(f"\n--- Analyzing File: {file_path} ---")
    # Read the PCAP and extract the exact same 6 features
    streamer = NFStreamer(source=file_path, statistical_analysis=True)
    
    results = []
    for flow in streamer:
        # Only look at flows with enough data to be meaningful
        if flow.bidirectional_packets > 0:
            # Inside your loop, add this print to see the 'culprit' feature:
            feat_data = {
                'bidirectional_packets': flow.bidirectional_packets,
                'bidirectional_bytes': flow.bidirectional_bytes,
                'bidirectional_mean_ps': flow.bidirectional_mean_ps,
                'bidirectional_iat_std': flow.bidirectional_stddev_piat_ms,
                'src2dst_bytes': flow.src2dst_bytes,
                'dst2src_bytes': flow.dst2src_bytes
            }
            prediction = model.predict(pd.DataFrame([feat_data]))[0]
            results.append(prediction)
            # print(f"Flow: {flow.bidirectional_bytes} bytes | MeanPS: {flow.bidirectional_mean_ps} | Pred: {prediction}")
    
    # Show the Mentor the summary
    if results:
        print(f"Total Flows Detected: {len(results)}")
        print(f"Streaming Detected: {results.count('Streaming')} times")
        print(f"Web Detected:  {results.count('Web')}")
        print(f"Generic UDP Detected:  {results.count('Generic_UDP')}")
    else:
        print("No significant flows found.")

# Run the test
test_pcap('youtube_1.pcapng')
test_pcap('web_1.pcapng')