import os
import sys
import time
import json
from typing import Dict, Any, List
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

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
    print('=' * 70, flush=True)
    print('Zero-Trust Identity Threat Detection Evaluation Harness', flush=True)
    print('=' * 70, flush=True)

    print('[*] Generating synthetic per-session telemetry datasets...', flush=True)
    train_benign = generate_benign_sessions(count=300, seed=1001)
    test_benign = generate_benign_sessions(count=100, seed=2002)
    test_cred_stuff = generate_credential_stuffing_sessions(count=50, seed=3003)
    test_imp_travel = generate_impossible_travel_sessions(count=50, seed=4004)
    test_push_bomb = generate_mfa_push_bombing_sessions(count=50, seed=5005)
    test_blended = generate_blended_pattern_sessions(count=30, seed=6006)

    print('    - Benign Training Baseline : ' + str(len(train_benign)) + ' sessions', flush=True)
    print('    - Held-out Benign Test Set : ' + str(len(test_benign)) + ' sessions', flush=True)
    print('    - Credential Stuffing      : ' + str(len(test_cred_stuff)) + ' sessions', flush=True)
    print('    - Impossible Travel        : ' + str(len(test_imp_travel)) + ' sessions', flush=True)
    print('    - MFA Push-Bombing         : ' + str(len(test_push_bomb)) + ' sessions', flush=True)
    print('    - Held-out Blended Pattern : ' + str(len(test_blended)) + ' sessions (Generalisation Check)', flush=True)

    print('[*] Training IsolationForest detector on benign baseline...', flush=True)
    detector = IdentityThreatDetector(contamination=0.04, random_state=42)
    detector.train_on_baseline(train_benign)

    benign_preds = [detector.score_session(s)[0] for s in test_benign]
    fp_count = sum(1 for p in benign_preds if p)
    tn_count = sum(1 for p in benign_preds if not p)
    fpr = fp_count / len(test_benign)

    categories = {
        'Credential Stuffing (T1110.003)': test_cred_stuff,
        'Impossible Travel (T1078)': test_imp_travel,
        'MFA Push-Bombing (T1621)': test_push_bomb
    }

    per_category_metrics = {}

    for cat_name, attack_sessions in categories.items():
        attack_preds = [detector.score_session(s)[0] for s in attack_sessions]
        tp = sum(1 for p in attack_preds if p)
        fn = sum(1 for p in attack_preds if not p)
        
        precision = tp / (tp + fp_count) if (tp + fp_count) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        per_category_metrics[cat_name] = {
            'samples': len(attack_sessions),
            'tp': tp,
            'fn': fn,
            'fp': fp_count,
            'tn': tn_count,
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1)
        }

    blended_preds = [detector.score_session(s)[0] for s in test_blended]
    b_tp = sum(1 for p in blended_preds if p)
    b_fn = sum(1 for p in blended_preds if not p)
    b_precision = b_tp / (b_tp + fp_count) if (b_tp + fp_count) > 0 else 0.0
    b_recall = b_tp / (b_tp + b_fn) if (b_tp + b_fn) > 0 else 0.0
    b_f1 = (2 * b_precision * b_recall) / (b_precision + b_recall) if (b_precision + b_recall) > 0 else 0.0

    blended_metrics = {
        'samples': len(test_blended),
        'tp': b_tp,
        'fn': b_fn,
        'fp': fp_count,
        'tn': tn_count,
        'precision': float(b_precision),
        'recall': float(b_recall),
        'f1_score': float(b_f1)
    }

    print('[*] Benchmarking latency overhead across 500 request cycles...', flush=True)
    t0 = time.perf_counter()
    for _ in range(500):
        _ = {'status': 'ok', 'content': 'Sample content'}
    t_baseline = (time.perf_counter() - t0) / 500.0 * 1000.0

    token = create_access_token(user_id='benchmark_user', role='analyst')
    t1 = time.perf_counter()
    for _ in range(500):
        _ = create_access_token(user_id='benchmark_user', role='analyst')
        ct, wrapped = EnvelopeCrypto.encrypt_case_content('Top secret benchmark case content')
        _ = EnvelopeCrypto.decrypt_case_content(ct, wrapped)
        f_ct = FieldCrypto.encrypt_field('SYNTHETIC_SSN_12345')
        _ = FieldCrypto.decrypt_field(f_ct)
    t_full_stack = (time.perf_counter() - t1) / 500.0 * 1000.0
    latency_delta = t_full_stack - t_baseline

    print('    - Baseline Response Latency    : ' + format(t_baseline, '.3f') + ' ms', flush=True)
    print('    - Full Security Stack Latency  : ' + format(t_full_stack, '.3f') + ' ms', flush=True)
    print('    - Cryptographic & Auth Overhead: +' + format(latency_delta, '.3f') + ' ms', flush=True)

    results = {
        'benign_baseline': {
            'total_test_samples': len(test_benign),
            'false_positives': fp_count,
            'true_negatives': tn_count,
            'false_positive_rate': float(fpr)
        },
        'per_category_metrics': per_category_metrics,
        'held_out_blended_pattern': blended_metrics,
        'latency_benchmarks': {
            'baseline_ms': float(t_baseline),
            'full_stack_ms': float(t_full_stack),
            'overhead_ms': float(latency_delta)
        }
    }

    print('=' * 70, flush=True)
    print('{:<35} | {:<7} | {:<6} | {:<6} | {:<6}'.format('Attack Category', 'Samples', 'P', 'R', 'F1'), flush=True)
    print('-' * 70, flush=True)
    for cat, m in per_category_metrics.items():
        print('{:<35} | {:^7} | {:.4f} | {:.4f} | {:.4f}'.format(cat, m['samples'], m['precision'], m['recall'], m['f1_score']), flush=True)
    print('-' * 70, flush=True)
    print('{:<35} | {:^7} | {:.4f} | {:.4f} | {:.4f}'.format('Held-out Blended (Generalisation)', blended_metrics['samples'], blended_metrics['precision'], blended_metrics['recall'], blended_metrics['f1_score']), flush=True)
    print('=' * 70, flush=True)
    print('Benign False Positive Rate: ' + format(fpr * 100, '.2f') + '% (' + str(fp_count) + '/' + str(len(test_benign)) + ')', flush=True)

    return results

if __name__ == '__main__':
    res = evaluate_detector()
    with open('docs/eval_results.json', 'w', encoding='utf-8') as f:
        json.dump(res, f, indent=2)
    print('[+] Saved raw metrics to docs/eval_results.json', flush=True)
