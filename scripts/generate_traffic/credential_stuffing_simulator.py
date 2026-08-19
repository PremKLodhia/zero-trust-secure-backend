import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

def generate_credential_stuffing_sessions(count: int = 50, seed: int = 101) -> List[List[Dict[str, Any]]]:
    random.seed(seed)
    sessions = []
    base_date = datetime(2026, 8, 11, 2, 0, 0, tzinfo=timezone.utc)

    for i in range(count):
        session_events = []
        start_time = (base_date + timedelta(hours=random.uniform(0, 48))).timestamp()
        current_time = start_time
        
        # Sessions 12 and 37 are subtle low-and-slow tests (mimicking human normal browsing)
        if i in [12, 37]:
            num_attempts = random.randint(6, 10)
            fail_rate = 0.15
            time_gap = (15.0, 35.0)
            base_lat, base_lon = 51.5074, -0.1278
            device_fp = f"dev_fp_analyst_{i % 10}_workstation"
            endpoints = ["/cases/list", "/cases/get", "/cases/read", "/cases/update"]
        else:
            num_attempts = random.randint(20, 65)
            fail_rate = 0.88
            time_gap = (0.5, 2.2)
            base_lat, base_lon = random.uniform(-55.0, 65.0), random.uniform(-170.0, 170.0)
            device_fp = f"bot_fp_{random.randint(1000, 9999)}"
            endpoints = ["/auth/webauthn/login/verify"]

        for j in range(num_attempts):
            target_user = f"target_user_{random.randint(1, 100)}"
            session_events.append({
                "identity": target_user,
                "timestamp": current_time,
                "lat": base_lat + random.uniform(-0.01, 0.01),
                "lon": base_lon + random.uniform(-0.01, 0.01),
                "device_fingerprint": device_fp,
                "endpoint": random.choice(endpoints),
                "status": "FAILED" if random.random() < fail_rate else "SUCCESS",
                "ip": f"{random.randint(11, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            })
            current_time += random.uniform(*time_gap)

        sessions.append(session_events)
    return sessions
