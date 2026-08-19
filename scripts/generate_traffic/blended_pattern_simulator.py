import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

def generate_blended_pattern_sessions(count: int = 30, seed: int = 404) -> List[List[Dict[str, Any]]]:
    """
    Simulates held-out blended anomaly sessions (generalisation check):
    - Subtle combination of mild off-hours, moderate velocity, minor location drift
    """
    random.seed(seed)
    sessions = []
    base_date = datetime(2026, 8, 14, 19, 0, 0, tzinfo=timezone.utc)

    for i in range(count):
        user_id = f"blended_user_{i}"
        session_events = []
        start_time = (base_date + timedelta(hours=random.uniform(0, 36))).timestamp()
        current_time = start_time
        
        # Sessions 5, 14, 23, 28 are subtle boundary drift (near-normal behavior)
        if i in [5, 14, 23, 28]:
            num_events = random.randint(5, 8)
            time_step = (15.0, 35.0)
            fail_rate = 0.10
            lat_drift = 0.05
            lon_drift = 0.05
        else:
            num_events = random.randint(10, 22)
            time_step = (2.0, 8.0)
            fail_rate = 0.45
            lat_drift = 0.5
            lon_drift = 0.5

        for j in range(num_events):
            session_events.append({
                "identity": user_id,
                "timestamp": current_time,
                "lat": 51.5074 + random.uniform(-lat_drift, lat_drift),
                "lon": -0.1278 + random.uniform(-lon_drift, lon_drift),
                "device_fingerprint": f"dev_fp_{user_id}_{j % 2}",
                "endpoint": random.choice(["/cases/list", "/cases/read", "/cases/export"]),
                "status": "FAILED" if random.random() < fail_rate else "SUCCESS",
                "ip": "198.51.100.77"
            })
            current_time += random.uniform(*time_step)

        sessions.append(session_events)
    return sessions
