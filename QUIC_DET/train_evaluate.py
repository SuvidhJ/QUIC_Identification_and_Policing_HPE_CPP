import pandas as pd
import numpy as np
import json
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, precision_recall_curve
import xgboost as xgb
import shap
import matplotlib.pyplot as plt
from datetime import datetime
from sklearn.preprocessing import StandardScaler

class QUICTrainer:
    def __init__(self, model_dir='models'):
        self.MIN_LONG_HEADER_EVIDENCE = 0.01
        self.model_dir = model_dir
        if not os.path.exists(self.model_dir):
            os.makedirs(self.model_dir)
        
        self.ml_features = [
        "short_header_ratio",
        "unique_versions",

        "packet_count",
        # "total_bytes",
        "duration",

        "bytes_per_sec",
        "packets_per_sec",

        "avg_pkt_size",
        "std_pkt_size",

        "avg_iat",
        "std_iat"
    ]

    def _impute_features(self, df):
        df_imputed = df.copy()

        for col in self.ml_features:

            if col not in df_imputed.columns:
                continue

            if col == "transport_protocol":
                df_imputed[col] = df_imputed[col].fillna(0)

            else:
                if df_imputed[col].isnull().all():
                    df_imputed[col] = 0
                else:
                    df_imputed[col] = df_imputed[col].fillna(
                        df_imputed[col].median()
                    )

        return df_imputed

    def _generate_feature_report(self, df):
        print("\n--- Feature Availability Report ---")
        rows = []
        for col in self.ml_features:

            missing_pct = df[col].isna().mean() * 100

            if pd.api.types.is_numeric_dtype(df[col]):
                mean_val = df[col].mean()
                zero_pct = (df[col] == 0).mean() * 100
                std_val = df[col].std()
            else:
                zero_pct="N/A"
                mean_val = "N/A"
                std_val = "N/A"

            rows.append([col, missing_pct, zero_pct, mean_val, std_val])
        
        report_df = pd.DataFrame(rows, columns=['Feature', 'Missing %', 'Zero %', 'Mean', 'Std'])
        print(report_df.to_string(index=False))
        
        # Optionally exclude features if missing > 90%
        excluded = report_df[report_df['Missing %'] > 90]['Feature'].tolist()
        if excluded:
            print(f"\nExcluding features due to high missing values: {excluded}")
            self.ml_features = [f for f in self.ml_features if f not in excluded]

    def _evaluate_tiers_separate(self, df, true_labels, true_tiers):
        # We assume dataset has 'label' and we have the predictions per tier
        pass

    def train_and_evaluate(self, df):
        print("Starting Model Training and Evaluation...")
        
        # Feature availability
        self._generate_feature_report(df)

        df_ml = df.copy()

        df_ml["transport_protocol"] = (
            df_ml["transport_protocol"]
            .astype(str)
            .str.upper()
        )

        df_ml = df_ml[
            df_ml["transport_protocol"] == "UDP"
        ].copy()
        protocol_map = {
            "UDP": 1,
            "TCP": 2,
            "DCCP": 4,
            "SCTP": 3
        }
        print("\nDEBUG transport_protocol sample:")
        print(df_ml["transport_protocol"].head(10))

        print("\nDEBUG transport_protocol type:")
        print(type(df_ml["transport_protocol"].iloc[0]))
        df_ml["transport_protocol"] = (
            df_ml["transport_protocol"]
            .map(protocol_map)
            .fillna(0)
        )
        print("\nProtocol Distribution:")
        print(df_ml["transport_protocol"].value_counts())
        if len(df_ml) == 0:
            print("No flows available for ML training after filtering.")
            return

        print(f"Total flows: {len(df)}, Flows eligible for ML: {len(df_ml)}")
        df_ml["label"] = (
            df_ml["label"]
            .map({
                "NON-QUIC": 0,
                "QUIC": 1
            })
        )

        quic_df = df_ml[df_ml["label"] == 1]
        non_quic_df = df_ml[df_ml["label"] == 0]

        sample_size = min(
            len(quic_df),
            len(non_quic_df)
        )

        quic_df = quic_df.sample(
            n=sample_size,
            random_state=42
        )

        non_quic_df = non_quic_df.sample(
            n=sample_size,
            random_state=42
        )

        df_ml = pd.concat(
            [quic_df, non_quic_df],
            ignore_index=True
        )

        df_ml = df_ml.sample(
            frac=1,
            random_state=42
        ).reset_index(drop=True)

        print("\nBalanced Dataset:")
        print(df_ml["label"].value_counts())
        X = df_ml[self.ml_features]
        X = self._impute_features(X)
        y = df_ml['label']

        if len(y.unique()) < 2:
            print("Not enough classes for ML training.")
            return
        X["short_header_ratio"] *= 5
        X["unique_versions"] *= 5
        # Train / Validation / Test Splits (60/20/20)
        X_temp, X_test, y_temp, y_test = train_test_split(X, y, test_size=0.2, random_state=42,stratify=y)
        X_train, X_val, y_train, y_val = train_test_split(X_temp, y_temp, test_size=0.25, random_state=42,stratify=y_temp) # 0.25 x 0.8 = 0.2
        
        # Cross-validation on Train Set
        print("\n--- 5-Fold Cross Validation ---")
        kf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        rf_aucs = []
        xgb_aucs = []
        
        for train_idx, val_idx in kf.split(X_train, y_train):
            X_tr_kf, X_val_kf = X_train.iloc[train_idx], X_train.iloc[val_idx]
            y_tr_kf, y_val_kf = y_train.iloc[train_idx], y_train.iloc[val_idx]
            
            rf_kf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
            rf_kf.fit(X_tr_kf, y_tr_kf)
            rf_aucs.append(roc_auc_score(y_val_kf, rf_kf.predict_proba(X_val_kf)[:, 1]))
            
            xgb_kf = xgb.XGBClassifier(
                n_estimators=500,
                max_depth=8,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                n_jobs=-1,
                eval_metric='logloss'
            )
            xgb_kf.fit(X_tr_kf, y_tr_kf)
            xgb_aucs.append(roc_auc_score(y_val_kf, xgb_kf.predict_proba(X_val_kf)[:, 1]))

        print(f"Random Forest CV Mean ROC-AUC: {np.mean(rf_aucs):.4f} (+/- {np.std(rf_aucs):.4f})")
        print(f"XGBoost CV Mean ROC-AUC: {np.mean(xgb_aucs):.4f} (+/- {np.std(xgb_aucs):.4f})")

        # Train final models on X_train + optimize thresholds on X_val
        rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        rf_model.fit(X_train, y_train)
        rf_val_preds = rf_model.predict_proba(X_val)[:, 1]
        rf_final_auc = roc_auc_score(y_val, rf_val_preds)

        xgb_model = xgb.XGBClassifier(n_estimators=500,
                max_depth=8,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                n_jobs=-1,
                eval_metric='logloss')
        xgb_model.fit(X_train, y_train)
        xgb_val_preds = xgb_model.predict_proba(X_val)[:, 1]
        xgb_final_auc = roc_auc_score(y_val, xgb_val_preds)

        if xgb_final_auc >= rf_final_auc:
            best_model = xgb_model
            best_name = "XGBoost"
            best_val_preds = xgb_val_preds
        else:
            best_model = rf_model
            best_name = "RandomForest"
            best_val_preds = rf_val_preds
            
        print(f"\nSelected Model: {best_name}")

        # Optimization on Validation Set
        precisions, recalls, thresholds = precision_recall_curve(y_val, best_val_preds)
        fsh = (2 * precisions * recalls) / (precisions + recalls + 1e-9)
        best_f1_idx = np.argmax(fsh)
        opt_thresh = thresholds[best_f1_idx] if best_f1_idx < len(thresholds) else 0.5
        
        quic_threshold = min(0.85, opt_thresh + 0.1)
        quic_probable_threshold = max(0.4, opt_thresh - 0.1)
        
        print("\n--- Validation Threshold Optimization ---")
        print(f"Optimal QUIC Threshold chosen: {quic_threshold:.4f}")
        print(f"Optimal QUIC_PROBABLE Threshold chosen: {quic_probable_threshold:.4f}")

        # Save model and metadata
        # Save Random Forest
        with open(
            os.path.join(self.model_dir, "random_forest.pkl"),
            "wb"
        ) as f:
            pickle.dump(rf_model, f)

        # Save XGBoost
        with open(
            os.path.join(self.model_dir, "xgboost.pkl"),
            "wb"
        ) as f:
            pickle.dump(xgb_model, f)

        print("Random Forest and XGBoost models saved.")
        with open(os.path.join(self.model_dir, 'best_model.pkl'), 'wb') as f:
            pickle.dump(best_model, f)
            
    
        feature_importance_dict = {
            feature: float(importance)
            for feature, importance in zip(
                self.ml_features,
                best_model.feature_importances_
            )
        }

        metadata = {
            "selected_model": best_name,

            "quic_threshold": float(quic_threshold),
            "quic_probable_threshold": float(quic_probable_threshold),

            "training_features": self.ml_features,
            "training_timestamp": datetime.now().isoformat(),

            "cross_validation": {
                "rf_mean_auc": float(np.mean(rf_aucs)),
                "rf_std_auc": float(np.std(rf_aucs)),
                "xgb_mean_auc": float(np.mean(xgb_aucs)),
                "xgb_std_auc": float(np.std(xgb_aucs))
            },

            "validation_auc": {
                "random_forest": float(rf_final_auc),
                "xgboost": float(xgb_final_auc)
            }
        }
        print("Model and Metadata Saved.")

        # Test set Final Evaluation
        print("\n--- Test Set Evaluation (Tier 3 ML Only) ---")
        test_preds_proba = best_model.predict_proba(X_test)[:, 1]
        test_preds_binary = [1 if p >= quic_probable_threshold else 0 for p in test_preds_proba]

        print(f"Accuracy: {accuracy_score(y_test, test_preds_binary):.4f}")
        print(f"Precision: {precision_score(y_test, test_preds_binary):.4f}")
        print(f"Recall: {recall_score(y_test, test_preds_binary):.4f}")
        print(f"F1 Score: {f1_score(y_test, test_preds_binary):.4f}")
        print(f"ROC-AUC: {roc_auc_score(y_test, test_preds_proba):.4f}")

        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, test_preds_binary))
        
        # Feature Importance & Entropy Verification
        importances = best_model.feature_importances_
        feature_imp = pd.DataFrame(sorted(zip(importances, self.ml_features)), columns=['Value','Feature'])
        print("\n--- Feature Importance Ranking ---")
        print(feature_imp.sort_values(by="Value", ascending=False).to_string(index=False))
        print("\n--- Error Analysis (False Positives & Negatives from ML Test Set) ---")
        errors_fp = []
        errors_fn = []
        # Let's map real label and pred and dump samples
        for idx_val, true_val, pred_val in zip(X_test.index, y_test, test_preds_binary):
            if true_val == 0 and pred_val == 1:
                errors_fp.append(idx_val)
            elif true_val == 1 and pred_val == 0:
                errors_fn.append(idx_val)
                
        print(f"False Positives: {len(errors_fp)}")
        print(f"False Negatives: {len(errors_fn)}")
        # Dump up to 3 samples for error analysis
        if len(errors_fp) > 0:
            print("\nSample False Positives (predicted QUIC, true NON_QUIC):")
            print(X_test.loc[errors_fp[:3]].to_string())
        if len(errors_fn) > 0:
            print("\nSample False Negatives (predicted NON_QUIC, true QUIC):")
            print(X_test.loc[errors_fn[:3]].to_string())
        # ----------------------------
        # Save Results JSON
        # ----------------------------

        results = {
            "selected_model": best_name,

            "metrics": {
                "accuracy": float(accuracy_score(y_test, test_preds_binary)),
                "precision": float(precision_score(y_test, test_preds_binary)),
                "recall": float(recall_score(y_test, test_preds_binary)),
                "f1_score": float(f1_score(y_test, test_preds_binary)),
                "roc_auc": float(roc_auc_score(y_test, test_preds_proba))
            },

            "confusion_matrix": (
                confusion_matrix(y_test, test_preds_binary)
                .tolist()
            ),

            "thresholds": {
                "quic_threshold": float(quic_threshold),
                "quic_probable_threshold": float(quic_probable_threshold)
            },

            "dataset": {
                "total_flows": int(len(df)),
                "ml_flows": int(len(df_ml)),
                "balanced_samples_per_class": int(sample_size)
            }
        }
        metadata["test_metrics"] = {
            "accuracy": float(accuracy_score(y_test, test_preds_binary)),
            "precision": float(precision_score(y_test, test_preds_binary)),
            "recall": float(recall_score(y_test, test_preds_binary)),
            "f1_score": float(f1_score(y_test, test_preds_binary)),
            "roc_auc": float(roc_auc_score(y_test, test_preds_proba))
        }

        metadata["confusion_matrix"] = (
            confusion_matrix(y_test, test_preds_binary).tolist()
        )

        metadata["feature_importances"] = dict(
            sorted(
                feature_importance_dict.items(),
                key=lambda x: x[1],
                reverse=True
            )
        )
        with open(
            os.path.join(self.model_dir, "best_model_results.json"),
            "w"
        ) as f:
            json.dump(results, f, indent=4)

        print("Results JSON saved.")
        print("\n--- SHAP Analysis ---")
        explainer = shap.TreeExplainer(best_model)
        shap_values = explainer.shap_values(X_test)
        
        shap.summary_plot(shap_values, X_test, feature_names=self.ml_features, show=False)
        plt.savefig(os.path.join(self.model_dir, 'shap_summary.png'), bbox_inches='tight')
        plt.close()
        
        shap.summary_plot(shap_values, X_test, feature_names=self.ml_features, plot_type="bar", show=False)
        plt.savefig(os.path.join(self.model_dir, 'shap_feature_importance.png'), bbox_inches='tight')
        plt.close()
        metadata["dataset"] = {
            "total_flows": int(len(df)),
            "ml_flows": int(len(df_ml)),
            "balanced_samples_per_class": int(sample_size)
        }

        metadata["num_features"] = len(self.ml_features)

        with open(
            os.path.join(self.model_dir, "metadata.json"),
            "w"
        ) as f:
            json.dump(metadata, f, indent=4)

        print("Metadata saved.")
        print("SHAP plots saved.")
        print("Completed Successfully")
if __name__ == '__main__':

    DATASET_PATH = "/Users/shubham_kumar/Downloads/QUIC_DET/final_dataset.csv"

    print(f"Loading dataset: {DATASET_PATH}")

    df = pd.read_csv(
        DATASET_PATH,
        low_memory=False
    )

    print(f"Loaded {len(df)} flows")
    print(
        pd.crosstab(
            df["transport_protocol"],
            df["label"]
        )
    )
    trainer = QUICTrainer()

    trainer.train_and_evaluate(df)