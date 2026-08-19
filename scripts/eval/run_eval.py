import os
import sys
import time
import json
from typing import Dict, Any, List
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.detection.model import IdentityThreatDetector
from scripts.generate_traffic.benign_simulator import generate_benign_sessions
from scripts.generate_traffic.credential_stuffing_simulator import generate_credential_stuffing_sessions
from scripts.generate_traffic.impossible_travel_simulator import generate_impossible_travel_sessions
from scripts.generate_traffic.mfa_push_bombing_simulator import generate_mfa_push_bombing_sessions
from scripts.generate_traffic.blended_pattern_simulator import generate_blended_pattern_sessions
from src.auth.tokens.service import create_access_token
from src.crypto.envelope import EnvelopeCrypto
from src.crypto.field_crypto import FieldCrypto

def evaluate_detector():
    print("=" * 75, flush=True)
    print("Zero-Trust Identity Threat Detection Empirical Evaluation Harness", flush=True)
    print("=" * 75, flush=True)

    print("[*] Generating synthetic per-session telemetry datasets...", flush=True)
    train_benign = generate_benign_sessions(count=300, seed=1001)
    test_benign = generate_benign_sessions(count=150, seed=2002)

    # Independent category test suites
    test_cred_stuff = generate_credential_stuffing_sessions(count=50, seed=3003)
    test_imp_travel = generate_impossible_travel_sessions(count=50, seed=4004)
    test_push_bomb = generate_mfa_push_bombing_sessions(count=50, seed=5005)
    test_blended = generate_blended_pattern_sessions(count=30, seed=6006)

    # Partition benign holdouts across category evaluation slices
    benign_slice_cred = test_benign[:50]
    benign_slice_travel = test_benign[50:100]
    benign_slice_push = test_benign[100:150]
    benign_slice_blend = test_benign[:30]

    print("    - Benign Training Baseline : " + str(len(train_benign)) + " sessions", flush=True)
    print("    - Total Held-out Benign    : " + str(len(test_benign)) + " sessions", flush=True)
    print("    - Credential Stuffing      : " + str(len(test_cred_stuff)) + " sessions (T1110.004)", flush=True)
    print("    - Impossible Travel        : " + str(len(test_imp_travel)) + " sessions (T1078)", flush=True)
    print("    - MFA Push-Bombing         : " + str(len(test_push_bomb)) + " sessions (T1621)", flush=True)
    print("    - Held-out Blended Pattern : " + str(len(test_blended)) + " sessions (Generalisation Check)", flush=True)

    print("[*] Training IsolationForest detector on benign baseline...", flush=True)
    detector = IdentityThreatDetector(contamination=0.04, random_state=42)
    detector.train_on_baseline(train_benign)

    # Global benign test evaluation
    global_benign_scores = [detector.score_session(s) for s in test_benign]
    global_fp = sum(1 for s in global_benign_scores if s[0])
    global_tn = len(test_benign) - global_fp
    global_fpr = global_fp / len(test_benign)

    categories = {
        "Credential Stuffing (T1110.004)": (test_cred_stuff, benign_slice_cred),
        "Impossible Travel (T1078)": (test_imp_travel, benign_slice_travel),
        "MFA Push-Bombing (T1621)": (test_push_bomb, benign_slice_push)
    }

    per_category_metrics = {}

    for cat_name, (attack_sessions, benign_slice) in categories.items():
        attack_scores = [detector.score_session(s) for s in attack_sessions]
        benign_slice_scores = [detector.score_session(s) for s in benign_slice]

        tp = sum(1 for s in attack_scores if s[0])
        fn = sum(1 for s in attack_scores if not s[0])
        fp = sum(1 for s in benign_slice_scores if s[0])
        tn = sum(1 for s in benign_slice_scores if not s[0])

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        raw_anomaly_scores = [float(s[1]) for s in attack_scores]

        per_category_metrics[cat_name] = {
            "samples": len(attack_sessions),
            "tp": int(tp),
            "fn": int(fn),
            "fp": int(fp),
            "tn": int(tn),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1_score": round(float(f1), 4),
            "mean_anomaly_score": round(float(np.mean(raw_anomaly_scores)), 4)
        }

    # Held-out blended generalisation check
    blended_scores = [detector.score_session(s) for s in test_blended]
    b_benign_scores = [detector.score_session(s) for s in benign_slice_blend]
    b_tp = sum(1 for s in blended_scores if s[0])
    b_fn = sum(1 for s in blended_scores if not s[0])
    b_fp = sum(1 for s in b_benign_scores if s[0])
    b_tn = sum(1 for s in b_benign_scores if not s[0])

    b_precision = b_tp / (b_tp + b_fp) if (b_tp + b_fp) > 0 else 0.0
    b_recall = b_tp / (b_tp + b_fn) if (b_tp + b_fn) > 0 else 0.0
    b_f1 = (2 * b_precision * b_recall) / (b_precision + b_recall) if (b_precision + b_recall) > 0 else 0.0

    blended_metrics = {
        "samples": len(test_blended),
        "tp": int(b_tp),
        "fn": int(b_fn),
        "fp": int(b_fp),
        "tn": int(b_tn),
        "precision": round(float(b_precision), 4),
        "recall": round(float(b_recall), 4),
        "f1_score": round(float(b_f1), 4),
        "mean_anomaly_score": round(float(np.mean([float(s[1]) for s in blended_scores])), 4)
    }

    print("[*] Benchmarking latency overhead across 500 request cycles...", flush=True)
    t0 = time.perf_counter()
    for _ in range(500):
        _ = {"status": "ok", "content": "Sample content"}
    t_baseline = (time.perf_counter() - t0) / 500.0 * 1000.0

    t1 = time.perf_counter()
    for _ in range(500):
        _ = create_access_token(user_id="benchmark_user", role="analyst")
        ct, wrapped = EnvelopeCrypto.encrypt_case_content("Top secret benchmark case content")
        _ = EnvelopeCrypto.decrypt_case_content(ct, wrapped)
        f_ct = FieldCrypto.encrypt_field("SYNTHETIC_SSN_12345")
        _ = FieldCrypto.decrypt_field(f_ct)
    t_full_stack = (time.perf_counter() - t1) / 500.0 * 1000.0
    latency_delta = t_full_stack - t_baseline

    print("    - Baseline Response Latency    : " + format(t_baseline, ".3f") + " ms", flush=True)
    print("    - Full Security Stack Latency  : " + format(t_full_stack, ".3f") + " ms", flush=True)
    print("    - Cryptographic & Auth Overhead: +" + format(latency_delta, ".3f") + " ms", flush=True)

    results = {
        "benign_baseline": {
            "total_test_samples": len(test_benign),
            "false_positives": int(global_fp),
            "true_negatives": int(global_tn),
            "false_positive_rate": round(float(global_fpr), 4),
            "operational_handling": "Tuned for high recall in forensic case exchange; flagged sessions route to SOC analyst review rather than automated lockouts"
        },
        "per_category_metrics": per_category_metrics,
        "held_out_blended_pattern": blended_metrics,
        "latency_benchmarks": {
            "baseline_ms": round(float(t_baseline), 4),
            "full_stack_ms": round(float(t_full_stack), 4),
            "overhead_ms": round(float(latency_delta), 4)
        }
    }

    print("=" * 75, flush=True)
    print("{:<35} | {:<7} | {:<4} | {:<4} | {:<6} | {:<6} | {:<6}".format("Attack Category", "Samples", "TP", "FN", "P", "R", "F1"), flush=True)
    print("-" * 75, flush=True)
    for cat, m in per_category_metrics.items():
        print("{:<35} | {:^7} | {:^4} | {:^4} | {:.4f} | {:.4f} | {:.4f}".format(cat, m["samples"], m["tp"], m["fn"], m["precision"], m["recall"], m["f1_score"]), flush=True)
    print("-" * 75, flush=True)
    print("{:<35} | {:^7} | {:^4} | {:^4} | {:.4f} | {:.4f} | {:.4f}".format("Held-out Blended (Generalisation)", blended_metrics["samples"], blended_metrics["tp"], blended_metrics["fn"], blended_metrics["precision"], blended_metrics["recall"], blended_metrics["f1_score"]), flush=True)
    print("=" * 75, flush=True)
    print("Benign False Positive Rate: " + format(global_fpr * 100, ".2f") + "% (" + str(global_fp) + "/" + str(len(test_benign)) + ")", flush=True)

    return results

if __name__ == "__main__":
    res = evaluate_detector()
    with open("docs/eval_results.json", "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    print("[+] Saved raw metrics to docs/eval_results.json", flush=True)
