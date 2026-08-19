import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

GLOBAL_LOCATIONS = [
    ("London_UK", 51.5074, -0.1278),
    ("Tokyo_Japan", 35.6762, 139.6503),
    ("Sydney_Australia", -33.8688, 151.2093),
    ("SaoPaulo_Brazil", -23.5505, -46.6333),
    ("SanFrancisco_US", 37.7749, -122.4194),
    ("Paris_France", 48.8566, 2.3522),
    ("Reading_UK", 51.4543, -0.9781),
]

def generate_impossible_travel_sessions(count: int = 50, seed: int = 202) -> List[List[Dict[str, Any]]]:
    random.seed(seed)
    sessions = []
    base_date = datetime(2026, 8, 12, 10, 0, 0, tzinfo=timezone.utc)

    for i in range(count):
        user_id = f"travel_victim_{i}"
        session_events = []
        start_time = (base_date + timedelta(hours=random.uniform(0, 24))).timestamp()

        loc_a = GLOBAL_LOCATIONS[0]
        # Session 23 is a legitimate domestic commute (London to Reading in 60 mins -> ~60 km/h)
        if i == 23:
            loc_b = GLOBAL_LOCATIONS[6]
            jump_window = 3600.0  # 60 mins
            is_compromised = False
        else:
            loc_b = random.choice(GLOBAL_LOCATIONS[1:5])
            jump_window = random.uniform(180.0, 600.0)
            is_compromised = True

        session_events.append({
            "identity": user_id,
            "timestamp": start_time,
            "lat": loc_a[1],
            "lon": loc_a[2],
            "device_fingerprint": f"dev_fp_{user_id}_workstation",
            "endpoint": "/cases/list",
            "status": "SUCCESS",
            "ip": "81.2.69.142"
        })

        jump_time = start_time + jump_window
        session_events.append({
            "identity": user_id,
            "timestamp": jump_time,
            "lat": loc_b[1],
            "lon": loc_b[2],
            "device_fingerprint": f"dev_fp_{user_id}_compromised" if is_compromised else f"dev_fp_{user_id}_workstation",
            "endpoint": "/cases/export" if is_compromised else "/cases/read",
            "status": "SUCCESS",
            "ip": "203.0.113.88" if is_compromised else "81.2.69.142"
        })

        for k in range(random.randint(2, 4)):
            jump_time += random.uniform(15.0, 45.0)
            session_events.append({
                "identity": user_id,
                "timestamp": jump_time,
                "lat": loc_b[1],
                "lon": loc_b[2],
                "device_fingerprint": f"dev_fp_{user_id}_compromised" if is_compromised else f"dev_fp_{user_id}_workstation",
                "endpoint": "/cases/read",
                "status": "SUCCESS",
                "ip": "203.0.113.88" if is_compromised else "81.2.69.142"
            })

        sessions.append(session_events)
    return sessions
