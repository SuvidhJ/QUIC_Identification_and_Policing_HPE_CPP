import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

df = pd.read_csv('quic_dataset.csv')

features = [
    'bidirectional_packets', 
    'bidirectional_bytes', 
    'bidirectional_mean_ps', 
    'bidirectional_iat_std', 
    'src2dst_bytes', 
    'dst2src_bytes'
]

x = df[features]
y = df['label']

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size = 0.2, random_state = 42)

# We use Random Forest because it handles "overlapping" features (like your IAT) very well.
model = RandomForestClassifier(n_estimators = 100, random_state = 42)
model.fit(x_train, y_train)

# Evaluation
y_pred = model.predict(x_test)
print("---- MODEL PERFORMANCE ----")
print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
print('\n--- Details ---')
print(classification_report(y_test, y_pred))

joblib.dump(model, 'quic_classifier.pkl')
print('\nSuccess! Model saved!')