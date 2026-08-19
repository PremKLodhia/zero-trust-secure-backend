from typing import List, Dict, Any
import numpy as np
from datetime import datetime, timezone
from src.telemetry.geo import calculate_travel_speed_kmh

class TelemetryFeatureExtractor:
    """
    Engineers behavioral identity features per session / identity window:
    1. request_velocity: requests per minute
    2. max_travel_speed_kmh: peak geographical velocity between consecutive requests
    3. device_switch_count: number of distinct device fingerprints observed
    4. off_hours_score: deviation from typical 08:00-18:00 working hours (0.0=normal, 1.0=deep night)
    5. failed_auth_ratio: ratio of failed requests or login errors to total events
    6. endpoint_entropy: variety of sensitive endpoints accessed in burst
    """

    FEATURE_NAMES = [
        "request_velocity",
        "max_travel_speed_kmh",
        "device_switch_count",
        "off_hours_score",
        "failed_auth_ratio",
        "endpoint_entropy"
    ]

    @classmethod
    def extract_session_features(cls, events: List[Dict[str, Any]]) -> List[float]:
        if not events:
            return [0.0] * len(cls.FEATURE_NAMES)

        # 1. Request velocity (req/min)
        timestamps = [e["timestamp"] for e in events]
        min_t, max_t = min(timestamps), max(timestamps)
        duration_mins = max((max_t - min_t) / 60.0, 0.1)
        velocity = len(events) / duration_mins

        # 2. Impossible Travel Speed (max km/h between any consecutive points)
        max_speed = 0.0
        for i in range(len(events) - 1):
            e1, e2 = events[i], events[i + 1]
            loc1 = (e1.get("lat", 51.5074), e1.get("lon", -0.1278))
            loc2 = (e2.get("lat", 51.5074), e2.get("lon", -0.1278))
            speed = calculate_travel_speed_kmh(loc1, e1["timestamp"], loc2, e2["timestamp"])
            if speed > max_speed:
                max_speed = speed

        # 3. Device Switch Count
        devices = set(e.get("device_fingerprint", "fp_default") for e in events)
        device_switch_count = float(len(devices) - 1)

        # 4. Off-Hours Score
        # Typical working hours: 8am to 6pm UTC (8.0 to 18.0)
        off_hours_penalties = []
        for e in events:
            dt = datetime.fromtimestamp(e["timestamp"], tz=timezone.utc)
            hour = dt.hour + (dt.minute / 60.0)
            if 8.0 <= hour <= 18.0:
                off_hours_penalties.append(0.0)
            else:
                dist_to_work = min(abs(hour - 8.0), abs(hour - 18.0), abs((hour + 24) - 18.0))
                off_hours_penalties.append(min(dist_to_work / 6.0, 1.0))
        off_hours_score = float(np.mean(off_hours_penalties)) if off_hours_penalties else 0.0

        # 5. Failed Auth Ratio
        failed_count = sum(1 for e in events if e.get("status") in ["DENIED", "FAILED", 401, 403])
        failed_auth_ratio = float(failed_count / len(events))

        # 6. Endpoint Entropy
        endpoints = [e.get("endpoint", "/cases") for e in events]
        unique_eps, counts = np.unique(endpoints, return_counts=True)
        probs = counts / len(endpoints)
        entropy = float(-np.sum(probs * np.log2(probs + 1e-9)))

        return [
            float(velocity),
            float(max_speed),
            float(device_switch_count),
            float(off_hours_score),
            float(failed_auth_ratio),
            float(entropy)
        ]
