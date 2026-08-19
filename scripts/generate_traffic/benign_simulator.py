import random
import time
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

def generate_benign_sessions(count: int = 200, seed: int = 42) -> List[List[Dict[str, Any]]]:
    """
    Generates realistic benign analyst sessions:
    - Business hours (08:30 to 17:30 UTC)
    - Consistent corporate office / VPN location (London: 51.5074, -0.1278)
    - Consistent device fingerprint per user
    - Normal browsing/investigative velocity (1 to 5 req/min)
    - High success rate (status = SUCCESS)
    """
    random.seed(seed)
    sessions = []
    base_date = datetime(2026, 8, 10, 9, 0, 0, tzinfo=timezone.utc)

    for i in range(count):
        user_id = f"analyst_{i % 15}"
        device_fp = f"dev_fp_{user_id}_macbook"
        session_events = []

        # Random start hour between 08:30 and 16:30
        day_offset = i // 20
        start_hour = random.uniform(8.5, 16.5)
        session_start = base_date + timedelta(days=day_offset, hours=start_hour)
        current_time = session_start.timestamp()

        # 5 to 15 actions per session
        num_actions = random.randint(5, 15)
        for _ in range(num_actions):
            action = random.choice(["LIST_CASES", "GET_CASE", "UPDATE_CASE", "READ_CASE"])
            session_events.append({
                "identity": user_id,
                "timestamp": current_time,
                "lat": 51.5074 + random.uniform(-0.01, 0.01),
                "lon": -0.1278 + random.uniform(-0.01, 0.01),
                "device_fingerprint": device_fp,
                "endpoint": f"/cases/{action.lower()}",
                "status": "SUCCESS",
                "ip": "198.51.100.25"
            })
            # 10 to 45 seconds between analyst actions
            current_time += random.uniform(10.0, 45.0)

        sessions.append(session_events)
    return sessions
