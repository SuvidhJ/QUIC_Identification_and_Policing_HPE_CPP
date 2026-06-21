import pandas as pd
import numpy as np
import json
import pickle
import os
import time
from sklearn.metrics import accuracy_score, precision_score
from sklearn.metrics import recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
class QUICDetector:
    def __init__(self, model_dir='models'):
        self.MIN_LONG_HEADER_EVIDENCE = 0
        self.MEMORY_TTL_SECONDS = 180
        # since after this the flow is considered probably inactive
        self.MAX_CID_MEMORY = 10000
        self.MAX_TUPLE_MEMORY = 10000

        self.cid_memory = {}
        self.tuple_memory = {}
        
        metadata_path = os.path.join(model_dir, 'metadata.json')
        model_path = os.path.join(model_dir, 'best_model.pkl')
        
        if not os.path.exists(metadata_path) or not os.path.exists(model_path):
            raise FileNotFoundError(f"Model or metadata not found in {model_dir}. Need to train first.")
            
        with open(metadata_path, 'r') as f:
            self.metadata = json.load(f)
            
        self.quic_threshold = self.metadata['quic_threshold']
        self.quic_probable_threshold = self.metadata['quic_probable_threshold']
        self.ml_features = self.metadata['training_features']
        
        with open(model_path, 'rb') as f:
            self.ml_model = pickle.load(f)

    def _impute_flow(self, flow):
        imputed_flow = flow.copy()
        for col in self.ml_features:
            val = imputed_flow.get(col, np.nan)
            if pd.isna(val):
                imputed_flow[col] = 0.0
        return imputed_flow

    def _tier1_deterministic(self, flow):
        if flow.get('transport_protocol') != 'UDP':
            return 'NON_QUIC', 1.0, "Not proper transport protocol"

        long_header_ratio = flow.get('long_header_ratio', 0)
        fixed_bit_ratio = flow.get('fixed_bit_ratio', 0)
        valid_version_ratio = flow.get('valid_version_ratio', 0)
        unique_versions = flow.get('unique_versions', 0)

        if fixed_bit_ratio < 0.80:
            return 'NON_QUIC', 1.0, "Fixed bit ratio insufficient"

        if long_header_ratio >= self.MIN_LONG_HEADER_EVIDENCE:
            if valid_version_ratio > 0 and unique_versions >= 1:
                return 'QUIC', 1.0, "Valid Long Header & Version signature"
            
            # Note: Ambiguous Long Header flows without a recognized valid version 
            # should fallthrough to ML or Tier-2, resolving aggressive NON_QUIC tagging.
            
        return None, None, None

    def _tier2_handshake(self, flow):
        long_header_ratio = flow.get('long_header_ratio', 0)
        # Verify conservative criteria: must have long_header representation explicitly
        if long_header_ratio >= self.MIN_LONG_HEADER_EVIDENCE:
            init_rt = flow.get('initial_packet_ratio', 0)
            hs_rt = flow.get('handshake_packet_ratio', 0)
            retry_rt = flow.get('retry_packet_ratio', 0)
            zrtt_rt = flow.get('zero_rtt_ratio', 0)
            vn_rt = flow.get('version_negotiation_ratio', 0)
            
            if init_rt > 0 or hs_rt > 0 or retry_rt > 0 or zrtt_rt > 0 or vn_rt > 0:
                return 'QUIC', 0.95, "QUIC handshake presence with valid sequence headers"
        
        return None, None, None

    def _clean_memory(self):
        now = time.time()
        self.cid_memory = {k: v for k, v in self.cid_memory.items() if now - v['timestamp'] < self.MEMORY_TTL_SECONDS}
        self.tuple_memory = {k: v for k, v in self.tuple_memory.items() if now - v['timestamp'] < self.MEMORY_TTL_SECONDS}

    def _get_5_tuple(self, flow):
        src_ip = flow.get('src_ip')
        dst_ip = flow.get('dst_ip')
        src_port = flow.get('src_port')
        dst_port = flow.get('dst_port')
        protocol = flow.get('transport_protocol', flow.get('protocol'))
        return (src_ip, dst_ip, src_port, dst_port, protocol)

    def _get_reverse_5_tuple(self, flow):
        t = self._get_5_tuple(flow)
        return (t[1], t[0], t[3], t[2], t[4])

    def _get_cids(self, flow):
        cids = []
        for key in ['dcid', 'scid', 'dcids', 'scids']:
            val = flow.get(key)
            if val:
                if isinstance(val, list):
                    cids.extend(val)
                else:
                    cids.append(val)
        return list(set(cids))

    def _tier3_memory_lookup(self, flow):
        self._clean_memory()
        
        now = time.time()
        cids = self._get_cids(flow)
        for cid in cids:
            if cid in self.cid_memory:
                mem = self.cid_memory[cid]
                if (now - mem['timestamp'] < self.MEMORY_TTL_SECONDS) and mem['label'] == 'QUIC' and mem['confidence'] >= 0.95:
                    return 'QUIC', 0.98, 'Tier 3 (Memory)', 'Previously observed QUIC Connection ID'

        return None, None, None, None

    def _tier3_ml(self, flow):
        self._clean_memory()
        flow_imputed = self._impute_flow(flow)
        x = pd.DataFrame([flow_imputed])[self.ml_features]
        
        try:
            p_quic = self.ml_model.predict_proba(x)[0][1]
        except AttributeError:
            p_quic = self.ml_model.predict_proba(x)[0][1]

        fwd_tuple = self._get_5_tuple(flow)
        rev_tuple = self._get_reverse_5_tuple(flow)
        
        now = time.time()
        tuple_mem = self.tuple_memory.get(fwd_tuple) or self.tuple_memory.get(rev_tuple)
        reason_extra = ""
        if tuple_mem and (now - tuple_mem['timestamp'] < self.MEMORY_TTL_SECONDS) and tuple_mem['label'] == 'QUIC' and tuple_mem['confidence'] >= 0.95:
            p_quic = min(p_quic + 0.10, 0.99)
            reason_extra = " (ML classification boosted by prior QUIC 5-tuple evidence)"

        if p_quic >= self.quic_threshold:
            return 'QUIC', p_quic, f"Probabilistic classification via Feature ML{reason_extra}"
        elif self.quic_probable_threshold <= p_quic < self.quic_threshold:
            return 'QUIC_PROBABLE', p_quic, f"Probabilistic classification via Feature ML{reason_extra}"
        else:
            return 'NON_QUIC', 1 - p_quic, f"Probabilistic classification via Feature ML{reason_extra}"

    def _update_memory(self, flow, label, confidence, tier):
    # Remove expired entries before inserting new ones
        self._clean_memory()

        # If memory is approaching limit, clean oldest entries
        if len(self.cid_memory) >= self.MAX_CID_MEMORY:
            oldest_cids = sorted(
                self.cid_memory.items(),
                key=lambda x: x[1]['timestamp']
            )[: max(1, self.MAX_CID_MEMORY // 10)]

            for cid, _ in oldest_cids:
                del self.cid_memory[cid]

        if len(self.tuple_memory) >= self.MAX_TUPLE_MEMORY:
            oldest_tuples = sorted(
                self.tuple_memory.items(),
                key=lambda x: x[1]['timestamp']
            )[: max(1, self.MAX_TUPLE_MEMORY // 10)]

            for key, _ in oldest_tuples:
                del self.tuple_memory[key]
        if tier not in ['Tier 1', 'Tier 2']:
            return
        if label == "QUIC" and confidence >= 0.95:
            now = time.time()

            cids = self._get_cids(flow)
            for cid in cids:
                self.cid_memory[cid] = {
                    'label': label,
                    'confidence': confidence,
                    'timestamp': now,
                    'evidence_type': tier
                }

            fwd_tuple = self._get_5_tuple(flow)

            if all(fwd_tuple[:4]):
                self.tuple_memory[fwd_tuple] = {
                    'label': label,
                    'confidence': confidence,
                    'timestamp': now,
                    'evidence_type': tier
                }
    def classify_flow(self, flow):
        """
        Classifies incoming parsed features dictionary sequentially by Tiers.
        Output: Label, Confidence, Tier, Reasoning
        """
        label, conf, reason = self._tier1_deterministic(flow)
        if label is not None:
            if label == 'QUIC':
                self._update_memory(flow, label, conf, 'Tier 1')
            return label, conf, 'Tier 1', reason

        label, conf, reason = self._tier2_handshake(flow)
        if label is not None:
            if label == 'QUIC':
                self._update_memory(flow, label, conf, 'Tier 2')
            return label, conf, 'Tier 2', reason

        mem_label, mem_conf, mem_tier, mem_reason = self._tier3_memory_lookup(flow)
        if mem_label is not None:
            if mem_label == 'QUIC':
                self._update_memory(flow, mem_label, mem_conf, mem_tier)
            return mem_label, mem_conf, mem_tier, mem_reason
            
        label, conf, reason = self._tier3_ml(flow)
        self._update_memory(flow, label, conf, 'Tier 3 ML')
        return label, conf, 'Tier 3', reason

if __name__ == "__main__":
    from sklearn.metrics import classification_report
    
    DATASET_PATH = "/Users/shubham_kumar/Downloads/QUIC_DET/flow_features_test2.0.csv"
    
    detector = QUICDetector(
        model_dir="/Users/shubham_kumar/Downloads/QUIC_DET/models"
    )
    # model_path = os.path.join(model_dir, 'best_model.pkl')
    df = pd.read_csv(DATASET_PATH)
    
    y_true = []
    y_pred = []
    
    tier_usage = {
        "Tier 1": 0,
        "Tier 2": 0,
        "Tier 3 (Memory)": 0,
        "Tier 3": 0
    }
    
    labels_distribution = {
        "Predicted QUIC": 0,
        "Predicted QUIC_PROBABLE": 0,
        "Predicted NON_QUIC": 0
    }
    
    predictions = []
    
    for _, row in df.iterrows():
        flow = row.to_dict()
        true_label = flow.get('label')
        
        pred_label, confidence, tier, reason = detector.classify_flow(flow)
        
        if f"Predicted {pred_label}" in labels_distribution:
            labels_distribution[f"Predicted {pred_label}"] += 1
        
        tier_usage[tier] = tier_usage.get(tier, 0) + 1
        
        mapped_pred = pred_label
        if pred_label == "NON_QUIC":
            mapped_pred = "NON-QUIC"
        elif pred_label == "QUIC_PROBABLE":
            mapped_pred = "QUIC"
            
        y_true.append(true_label)
        y_pred.append(mapped_pred)
        
        predictions.append({
            'true_label': true_label,
            'predicted_label': pred_label,
            'confidence': confidence,
            'tier': tier,
            'reason': reason
        })
        
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, pos_label='QUIC')
    rec = recall_score(y_true, y_pred, pos_label='QUIC')
    f1 = f1_score(y_true, y_pred, pos_label='QUIC')
    cm = confusion_matrix(y_true, y_pred, labels=['NON-QUIC', 'QUIC'])
    cr = classification_report(y_true, y_pred, labels=['QUIC', 'NON-QUIC'])
    
    num_quic = sum(1 for label in y_true if label == 'QUIC')
    num_non_quic = sum(1 for label in y_true if label == 'NON-QUIC')
    
    print(f"Dataset size: {len(y_true)}")
    print(f"Number of QUIC flows: {num_quic}")
    print(f"Number of NON-QUIC flows: {num_non_quic}")
    print(f"Accuracy: {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall: {rec:.4f}")
    print(f"F1: {f1:.4f}")
    print("Confusion Matrix:")
    print(cm)
    print("Classification Report:")
    print(cr)
    
    print("\nTier Distribution:")
    print(f"Tier 1: {tier_usage['Tier 1']}")
    print(f"Tier 2: {tier_usage['Tier 2']}")
    print(f"Tier 3 (Memory): {tier_usage['Tier 3 (Memory)']}")
    print(f"Tier 3: {tier_usage['Tier 3']}")
    
    print("\nLabel Distribution:")
    print(f"Predicted QUIC: {labels_distribution['Predicted QUIC']}")
    print(f"Predicted QUIC_PROBABLE: {labels_distribution['Predicted QUIC_PROBABLE']}")
    print(f"Predicted NON_QUIC: {labels_distribution['Predicted NON_QUIC']}")
    
    # Save hybrid predictions
    preds_df = pd.DataFrame(predictions)
    preds_df.to_csv("hybrid_predictions.csv", index=False)
    
    # Error analysis
    df['predicted_mapped'] = y_pred
    df['actual'] = y_true
    report_text = f"""
    Dataset Size: {len(y_true)}

    QUIC Flows: {num_quic}
    NON-QUIC Flows: {num_non_quic}

    Accuracy: {acc:.4f}
    Precision: {prec:.4f}
    Recall: {rec:.4f}
    F1 Score: {f1:.4f}

    Confusion Matrix:
    {cm}

    Tier Distribution:
    Tier 1: {tier_usage['Tier 1']}
    Tier 2: {tier_usage['Tier 2']}
    Tier 3 (Memory): {tier_usage['Tier 3 (Memory)']}
    Tier 3: {tier_usage['Tier 3']}

    Label Distribution:
    Predicted QUIC: {labels_distribution['Predicted QUIC']}
    Predicted QUIC_PROBABLE: {labels_distribution['Predicted QUIC_PROBABLE']}
    Predicted NON_QUIC: {labels_distribution['Predicted NON_QUIC']}
    """


