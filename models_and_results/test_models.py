import pandas as pd
import joblib

from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

# 🔷 Load new dataset
df = pd.read_csv("dataset2.csv")

# 🔷 Features (must match training)
X = df[['avg_pkt_size','std_dev','max_pkt_size','min_pkt_size',
        'pkt_count','avg_iat','iat_std','duration',
        'pkt_rate','size_iqr','burstiness']]

# 🔷 Load label encoder
le = joblib.load("label_encoder.pkl")

# 🔷 True labels
y_true = le.transform(df['label'])

# ================================
# 🌳 DECISION TREE
# ================================

dt = joblib.load("QUIC_DT.pkl")
pred_dt = dt.predict(X)

print("\n🔷 DECISION TREE RESULTS")
print("Accuracy:", accuracy_score(y_true, pred_dt))
print("\nConfusion Matrix:\n", confusion_matrix(y_true, pred_dt))
print("\nClassification Report:\n",
      classification_report(y_true, pred_dt, zero_division=0))


# ================================
# 🌲 RANDOM FOREST
# ================================

rf = joblib.load("QUIC_RF.pkl")
pred_rf = rf.predict(X)

print("\n🔷 RANDOM FOREST RESULTS")
print("Accuracy:", accuracy_score(y_true, pred_rf))
print("\nConfusion Matrix:\n", confusion_matrix(y_true, pred_rf))
print("\nClassification Report:\n",
      classification_report(y_true, pred_rf, zero_division=0))


# ================================
# ⚡ XGBOOST
# ================================

xgb = joblib.load("xgb_model.pkl")
pred_xgb = xgb.predict(X)

print("\n🔷 XGBOOST RESULTS")
print("Accuracy:", accuracy_score(y_true, pred_xgb))
print("\nConfusion Matrix:\n", confusion_matrix(y_true, pred_xgb))
print("\nClassification Report:\n",
      classification_report(y_true, pred_xgb, zero_division=0))


# ================================
# 📊 OPTIONAL: SAVE RESULTS
# ================================

df['DT_pred'] = le.inverse_transform(pred_dt)
df['RF_pred'] = le.inverse_transform(pred_rf)
df['XGB_pred'] = le.inverse_transform(pred_xgb)

df.to_csv("evaluation_results.csv", index=False)

print("\n✅ Results saved to evaluation_results.csv")