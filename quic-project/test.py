import pandas as pd
import joblib

# Load model
model = joblib.load('quic_classifier.pkl')

# Define the features exactly as they were in the training script
feature_names = [
    'bidirectional_packets', 
    'bidirectional_bytes', 
    'bidirectional_mean_ps', 
    'bidirectional_iat_std', 
    'src2dst_bytes', 
    'dst2src_bytes'
]

# Get importance
importances = model.feature_importances_
feature_importance_df = pd.DataFrame({'Feature': feature_names, 'Importance': importances})
print(feature_importance_df.sort_values(by='Importance', ascending=False))