import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

def generate_credential_stuffing_sessions(count: int = 50, seed: int = 101) -> List[List[Dict[str, Any]]]:
    """
    Simulates automated credential stuffing attacks:
    - High request velocity (30 to 80 attempts/min)
    - High failure rate (>80% status = FAILED/DENIED)
    - Rapidly rotating random IP addresses and device fingerprints
    - Distributed time of day
    """
    random.seed(seed)
    sessions = []
    base_date = datetime(2026, 8, 11, 2, 0, 0, tzinfo=timezone.utc)

    for i in range(count):
        session_events = []
        start_time = (base_date + timedelta(hours=random.uniform(0, 48))).timestamp()
        current_time = start_time
        num_attempts = random.randint(25, 60)

        for j in range(num_attempts):
            target_user = f"target_user_{random.randint(1, 100)}"
            session_events.append({
                "identity": target_user,
                "timestamp": current_time,
                "lat": random.uniform(-60.0, 60.0),
                "lon": random.uniform(-180.0, 180.0),
                "device_fingerprint": f"bot_fp_{random.randint(1000, 9999)}",
                "endpoint": "/auth/webauthn/login/verify",
                "status": "FAILED" if random.random() < 0.9 else "SUCCESS",
                "ip": f"{random.randint(11, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            })
            # Rapid 0.5 to 2.0 seconds between attempts
            current_time += random.uniform(0.5, 2.0)

        sessions.append(session_events)
    return sessions
