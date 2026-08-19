import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

# Distant synthetic coordinates
LOCATIONS = [
    ("London_UK", 51.5074, -0.1278),
    ("Tokyo_Japan", 35.6762, 139.6503),
    ("Sydney_Australia", -33.8688, 151.2093),
    ("SaoPaulo_Brazil", -23.5505, -46.6333),
    ("SanFrancisco_US", 37.7749, -122.4194)
]

def generate_impossible_travel_sessions(count: int = 50, seed: int = 202) -> List[List[Dict[str, Any]]]:
    """
    Simulates impossible travel anomaly sessions:
    - User performs valid action at Location A (e.g. London)
    - 5 to 15 minutes later, same user credentials used at Location B (e.g. Tokyo, 9,500 km away)
    - Computed velocity > 3,000 km/h (far exceeding physical commercial aviation speed)
    """
    random.seed(seed)
    sessions = []
    base_date = datetime(2026, 8, 12, 10, 0, 0, tzinfo=timezone.utc)

    for i in range(count):
        user_id = f"travel_victim_{i}"
        session_events = []
        start_time = (base_date + timedelta(hours=random.uniform(0, 24))).timestamp()

        loc_a_name, lat_a, lon_a = LOCATIONS[0]
        loc_b_name, lat_b, lon_b = random.choice(LOCATIONS[1:])

        # Legitimate origin event
        session_events.append({
            "identity": user_id,
            "timestamp": start_time,
            "lat": lat_a,
            "lon": lon_a,
            "device_fingerprint": f"dev_fp_{user_id}_primary",
            "endpoint": "/cases/list",
            "status": "SUCCESS",
            "ip": "81.2.69.142"
        })

        # Impossible jump 3 to 10 minutes later
        jump_time = start_time + random.uniform(180.0, 600.0)
        session_events.append({
            "identity": user_id,
            "timestamp": jump_time,
            "lat": lat_b,
            "lon": lon_b,
            "device_fingerprint": f"dev_fp_{user_id}_hijacked",
            "endpoint": "/cases/export",
            "status": "SUCCESS",
            "ip": "203.0.113.88"
        })

        # Subsequent actions from compromised origin
        for k in range(random.randint(2, 5)):
            jump_time += random.uniform(15.0, 60.0)
            session_events.append({
                "identity": user_id,
                "timestamp": jump_time,
                "lat": lat_b,
                "lon": lon_b,
                "device_fingerprint": f"dev_fp_{user_id}_hijacked",
                "endpoint": "/cases/read",
                "status": "SUCCESS",
                "ip": "203.0.113.88"
            })

        sessions.append(session_events)
    return sessions
