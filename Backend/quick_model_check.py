"""Quick local harness to exercise the AnomalyDetector and print audit info.

Run this from the Backend folder (where this file lives):

    python quick_model_check.py

It will instantiate the detector (which enforces a loaded ML model) and run a few
synthetic packet feature inferences. Results are printed and a CSV audit line is
written to `ml_ids_project/logs/model_audit.csv` for each inference.
"""
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Ensure ml_ids_project is on sys.path
sys.path.insert(0, str(HERE / "ml_ids_project"))

try:
    from api.utils.ml_classifier import AnomalyDetector
except Exception as e:
    print("Failed to import AnomalyDetector:", e)
    raise


def main():
    det = AnomalyDetector()

    # Create a few synthetic packets with varying sizes/protocols/timestamps
    ts = time.time()
    samples = [
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "TCP", "length": 60, "timestamp": ts},
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "TCP", "length": 1500, "timestamp": ts + 0.1},
        {"src_ip": "192.168.1.5", "dst_ip": "8.8.8.8", "protocol": "UDP", "length": 700, "timestamp": ts + 0.2},
        {"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "protocol": "TCP", "length": 1600, "timestamp": ts + 0.3},
    ]

    print("Running quick model checks (audit CSV will be appended to ml_ids_project/logs/model_audit.csv)")
    for i, f in enumerate(samples, 1):
        try:
            res = det.classify_packet(f)
            # Support both old (status,severity) and new return (status,severity,probs,pred_idx,pred_prob)
            if isinstance(res, tuple) and len(res) >= 5:
                status, sev, probs, pred_idx, pred_prob = res
            elif isinstance(res, tuple) and len(res) >= 2:
                status, sev = res[0], res[1]
                probs, pred_idx, pred_prob = [], -1, 0.0
            else:
                raise RuntimeError("Unexpected classifier return value")

            print(f"{i}: status={status}, severity={sev}, pred_idx={pred_idx}, pred_prob={pred_prob:.3f}, src={f['src_ip']}->{f['dst_ip']} proto={f['protocol']} len={f['length']}")
            if probs:
                print("    probs=", probs)
        except Exception as e:
            print(f"Inference failed for sample {i}: {e}")


if __name__ == "__main__":
    main()
