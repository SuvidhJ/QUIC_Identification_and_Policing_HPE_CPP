# train.py
import pandas as pd
import numpy as np
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

FEATURES = [
    "packet_count", "total_bytes", "duration_s", "bytes_per_sec",
    "mean_payload_len", "std_payload_len", "min_payload_len", "max_payload_len",
    "mean_iat", "std_iat", "min_iat", "max_iat",
    "burst_count", "upload_ratio",
]

def load(path, drop_labels=None):
    df = pd.read_csv(path)
    if drop_labels:
        df = df[~df["label"].isin(drop_labels)]
    return df

def main():
    train_df = load("training_data.csv", drop_labels=["audio"])
    test_df  = load("test_data.csv",     drop_labels=["audio"])

    print(f"[*] train: {len(train_df)} rows")
    print(train_df["label"].value_counts().to_string())
    print(f"\n[*] test: {len(test_df)} rows")
    print(test_df["label"].value_counts().to_string())

    le = LabelEncoder()
    le.fit(train_df["label"])
    print(f"\n[*] classes: {list(le.classes_)}")

    X_train = train_df[FEATURES].values
    y_train = le.transform(train_df["label"])
    X_test  = test_df[FEATURES].values
    y_test  = le.transform(test_df["label"])

    # compute class weights manually to handle imbalance
    counts = np.bincount(y_train)
    total  = len(y_train)
    # weight[i] = total / (n_classes * count[i])
    weights = total / (len(counts) * counts)
    sample_weights = np.array([weights[y] for y in y_train])

    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="mlogloss",
        random_state=42,
    )

    model.fit(
        X_train, y_train,
        sample_weight=sample_weights,
        eval_set=[(X_test, y_test)],
        verbose=50,
    )

    y_pred = model.predict(X_test)

    print("\n[*] classification report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=le.classes_, yticklabels=le.classes_)
    plt.title("Confusion Matrix")
    plt.ylabel("Actual")
    plt.xlabel("Predicted")
    plt.tight_layout()
    plt.savefig("confusion_matrix.png")
    print("[*] saved confusion_matrix.png")

    # feature importance
    importances = model.feature_importances_
    fi_df = pd.DataFrame({"feature": FEATURES, "importance": importances})
    fi_df = fi_df.sort_values("importance", ascending=False)
    print("\n[*] feature importances:")
    print(fi_df.to_string(index=False))

    joblib.dump(model, "model.pkl")
    joblib.dump(le,    "label_encoder.pkl")
    print("\n[*] saved model.pkl and label_encoder.pkl")

if __name__ == "__main__":
    main()