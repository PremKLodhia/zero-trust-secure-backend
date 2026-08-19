import math
from typing import Tuple, Dict, Any

SYNTHETIC_GEO_DB: Dict[str, Dict[str, Any]] = {}

def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculates great-circle distance between two points on a sphere (in km)."""
    R = 6371.0  # Earth radius in kilometers
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

def calculate_travel_speed_kmh(
    loc1: Tuple[float, float],
    time1: float,
    loc2: Tuple[float, float],
    time2: float
) -> float:
    """
    Computes effective physical travel speed between two events.
    Returns speed in km/h. If time delta is near 0, returns high velocity.
    """
    dist_km = haversine_distance_km(loc1[0], loc1[1], loc2[0], loc2[1])
    time_delta_hours = abs(time2 - time1) / 3600.0
    if time_delta_hours < 0.001:  # Less than ~3.6 seconds
        return dist_km / 0.001 if dist_km > 50.0 else 0.0
    return dist_km / time_delta_hours
