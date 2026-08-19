import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

def generate_blended_pattern_sessions(count: int = 30, seed: int = 404) -> List[List[Dict[str, Any]]]:
    """
    Simulates held-out subtle blended anomalies:
    - Not one extreme signal, but multiple weak signals combined:
      * Mild off-hours (20:30 UTC)
      * Moderate request velocity (8-12 req/min)
      * Slight device change (1 new fingerprint)
      * Medium distance jump (300 km in 20 mins ~ 900 km/h, e.g. edge of high-speed train/flight)
      * Occasional denied action
    - Used exclusively as the held-out generalisation check in evaluation.
    """
    random.seed(seed)
    sessions = []
    base_date = datetime(2026, 8, 14, 20, 30, 0, tzinfo=timezone.utc)

    for i in range(count):
        user_id = f"blended_user_{i}"
        session_events = []
        start_time = (base_date + timedelta(days=i % 5)).timestamp()
        current_time = start_time

        # London (51.5074, -0.1278) -> Paris (48.8566, 2.3522) in 25 mins (~340 km / 800 km/h)
        for step in range(8):
            lat = 51.5074 if step < 4 else 48.8566
            lon = -0.1278 if step < 4 else 2.3522
            fp = f"fp_primary_{user_id}" if step < 4 else f"fp_secondary_{user_id}"
            
            session_events.append({
                "identity": user_id,
                "timestamp": current_time,
                "lat": lat,
                "lon": lon,
                "device_fingerprint": fp,
                "endpoint": "/cases/list" if step % 2 == 0 else "/cases/update",
                "status": "SUCCESS" if step != 3 else "DENIED",
                "ip": "82.165.197.1" if step < 4 else "195.154.122.5"
            })
            current_time += random.uniform(20.0, 50.0)

        sessions.append(session_events)
    return sessions
