import pytest
from src.telemetry.geo import haversine_distance_km, calculate_travel_speed_kmh
from src.telemetry.features import TelemetryFeatureExtractor
from src.detection.model import IdentityThreatDetector
from scripts.generate_traffic.benign_simulator import generate_benign_sessions
from scripts.generate_traffic.credential_stuffing_simulator import generate_credential_stuffing_sessions
from scripts.generate_traffic.impossible_travel_simulator import generate_impossible_travel_sessions
from scripts.generate_traffic.mfa_push_bombing_simulator import generate_mfa_push_bombing_sessions
from scripts.generate_traffic.blended_pattern_simulator import generate_blended_pattern_sessions

def test_haversine_distance_calculation():
    # London (51.5074, -0.1278) to Paris (48.8566, 2.3522) is approx 343 km
    dist = haversine_distance_km(51.5074, -0.1278, 48.8566, 2.3522)
    assert 340.0 <= dist <= 350.0

def test_impossible_travel_velocity_calculation():
    loc_london = (51.5074, -0.1278)
    loc_tokyo = (35.6762, 139.6503)
    t1 = 1700000000.0
    t2 = t1 + 600.0  # 10 minutes later

    speed = calculate_travel_speed_kmh(loc_london, t1, loc_tokyo, t2)
    # London to Tokyo distance ~9,560 km in 10 mins = ~57,000 km/h
    assert speed > 50000.0

def test_feature_extractor_dimensions():
    sample_session = [
        {"identity": "u1", "timestamp": 1700000000.0, "lat": 51.5, "lon": -0.1, "device_fingerprint": "fp1", "status": "SUCCESS", "endpoint": "/cases/get"},
        {"identity": "u1", "timestamp": 1700000030.0, "lat": 51.5, "lon": -0.1, "device_fingerprint": "fp1", "status": "SUCCESS", "endpoint": "/cases/update"},
    ]
    feats = TelemetryFeatureExtractor.extract_session_features(sample_session)
    assert len(feats) == len(TelemetryFeatureExtractor.FEATURE_NAMES)
    assert feats[0] > 0.0  # request velocity
    assert feats[2] == 0.0 # device switch count (1 device = 0 switches)

def test_identity_threat_detector_training_and_classification():
    # 1. Generate datasets
    benign_train = generate_benign_sessions(count=100, seed=1)
    benign_test = generate_benign_sessions(count=20, seed=2)
    cred_stuffing = generate_credential_stuffing_sessions(count=20, seed=3)
    impossible_travel = generate_impossible_travel_sessions(count=20, seed=4)
    push_bombing = generate_mfa_push_bombing_sessions(count=20, seed=5)
    blended = generate_blended_pattern_sessions(count=10, seed=6)

    # 2. Train IsolationForest
    detector = IdentityThreatDetector(contamination=0.05, random_state=42)
    detector.train_on_baseline(benign_train)
    assert detector.is_fitted is True

    # 3. Score Benign Test (High normal rate)
    benign_anomalies = 0
    for s in benign_test:
        is_anom, score, feats = detector.score_session(s)
        if is_anom:
            benign_anomalies += 1
    # Expect false positive rate <= 15% on held-out benign
    assert (benign_anomalies / len(benign_test)) <= 0.15

    # 4. Score Attacks (High detection rate)
    cs_detected = sum(1 for s in cred_stuffing if detector.score_session(s)[0])
    it_detected = sum(1 for s in impossible_travel if detector.score_session(s)[0])
    pb_detected = sum(1 for s in push_bombing if detector.score_session(s)[0])

    assert cs_detected >= 18, f"Credential stuffing detection low: {cs_detected}/20"
    assert it_detected >= 18, f"Impossible travel detection low: {it_detected}/20"
    assert pb_detected >= 18, f"Push bombing detection low: {pb_detected}/20"
