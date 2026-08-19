import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

def generate_benign_sessions(count: int = 300, seed: int = 42) -> List[List[Dict[str, Any]]]:
    """
    Generates realistic benign analyst sessions with realistic enterprise noise:
    - Primary business hours (08:00 to 18:00 UTC) with occasional late/early shifts
    - Primarily corporate London office with occasional regional/remote connections
    - Single device fingerprint per user
    - Normal browsing/investigative velocity (1 to 6 req/min)
    - Low occasional error rate (occasional 401 token refresh or typo)
    """
    random.seed(seed)
    sessions = []
    base_date = datetime(2026, 8, 10, 8, 0, 0, tzinfo=timezone.utc)

    for i in range(count):
        user_id = f"analyst_{i % 20}"
        device_fp = f"dev_fp_{user_id}_workstation"
        session_events = []

        day_offset = i // 25
        # 90% normal hours (08:30 - 17:30), 10% on-call/early shifts (07:00 or 19:00)
        if random.random() < 0.90:
            start_hour = random.uniform(8.5, 17.0)
        else:
            start_hour = random.choice([random.uniform(6.5, 8.0), random.uniform(17.5, 20.5)])

        session_start = base_date + timedelta(days=day_offset, hours=start_hour)
        current_time = session_start.timestamp()

        # Location: London (51.5074, -0.1278) with minor GPS jitter
        base_lat = 51.5074 + random.uniform(-0.03, 0.03)
        base_lon = -0.1278 + random.uniform(-0.03, 0.03)

        num_actions = random.randint(6, 18)
        for act_idx in range(num_actions):
            action = random.choice(["list", "get", "update", "read", "audit"])
            # Occasional transient 401 or failed action (3% chance)
            status = "FAILED" if random.random() < 0.03 else "SUCCESS"
            
            session_events.append({
                "identity": user_id,
                "timestamp": current_time,
                "lat": base_lat + random.uniform(-0.005, 0.005),
                "lon": base_lon + random.uniform(-0.005, 0.005),
                "device_fingerprint": device_fp,
                "endpoint": f"/cases/{action}",
                "status": status,
                "ip": "198.51.100.25"
            })
            current_time += random.uniform(8.0, 40.0)

        sessions.append(session_events)
    return sessions
