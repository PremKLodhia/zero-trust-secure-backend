import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

def generate_mfa_push_bombing_sessions(count: int = 50, seed: int = 303) -> List[List[Dict[str, Any]]]:
    random.seed(seed)
    sessions = []
    base_date = datetime(2026, 8, 13, 2, 30, 0, tzinfo=timezone.utc)

    for i in range(count):
        user_id = f"fatigue_target_{i}"
        session_events = []
        
        # Sessions 8, 29, 44 are normal daytime re-prompts (1-2 attempts during standard working hours)
        if i in [8, 29, 44]:
            start_hour = random.uniform(10.0, 15.0)
            burst_len = random.randint(4, 7)
            delay_range = (25.0, 60.0)
            device_fp = f"dev_fp_{user_id}_workstation"
            fail_rate = 0.25
            endpoints = ["/cases/list", "/cases/get", "/cases/read"]
        else:
            start_hour = random.uniform(1.0, 5.0)
            burst_len = random.randint(15, 36)
            delay_range = (1.5, 4.0)
            device_fp = f"attacker_box_{random.randint(100, 999)}"
            fail_rate = 0.90
            endpoints = ["/auth/webauthn/login/verify"]

        start_time = (base_date.replace(hour=0, minute=0, second=0) + timedelta(hours=start_hour)).timestamp()
        current_time = start_time

        for j in range(burst_len):
            is_last = (j == burst_len - 1)
            status = "SUCCESS" if (is_last and random.random() < 0.3) else ("FAILED" if random.random() < fail_rate else "SUCCESS")
            session_events.append({
                "identity": user_id,
                "timestamp": current_time,
                "lat": 51.5074 + random.uniform(-0.01, 0.01),
                "lon": -0.1278 + random.uniform(-0.01, 0.01),
                "device_fingerprint": device_fp,
                "endpoint": random.choice(endpoints),
                "status": status,
                "ip": "198.51.100.42"
            })
            current_time += random.uniform(*delay_range)

        sessions.append(session_events)
    return sessions
