import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

def generate_mfa_push_bombing_sessions(count: int = 50, seed: int = 303) -> List[List[Dict[str, Any]]]:
    """
    Simulates MFA fatigue / push-bombing attacks (MITRE T1621):
    - 15 to 35 rapid MFA verification/prompt requests targeting one identity within 60-120 seconds
    - High frequency at off-peak night hours to induce user fatigue
    - High failure rate until potential fatigue compromise
    """
    random.seed(seed)
    sessions = []
    base_date = datetime(2026, 8, 13, 1, 30, 0, tzinfo=timezone.utc)

    for i in range(count):
        user_id = f"push_victim_{i}"
        session_events = []
        start_time = (base_date + timedelta(hours=random.uniform(0, 12))).timestamp()
        current_time = start_time
        num_prompts = random.randint(15, 35)

        for p in range(num_prompts):
            session_events.append({
                "identity": user_id,
                "timestamp": current_time,
                "lat": 40.7128 + random.uniform(-0.05, 0.05),
                "lon": -74.0060 + random.uniform(-0.05, 0.05),
                "device_fingerprint": "attacker_push_bot_v1",
                "endpoint": "/auth/webauthn/login/options",
                "status": "DENIED" if p < num_prompts - 1 else "FAILED",
                "ip": "198.51.100.77"
            })
            # 1 to 3 seconds burst interval
            current_time += random.uniform(1.0, 3.0)

        sessions.append(session_events)
    return sessions
