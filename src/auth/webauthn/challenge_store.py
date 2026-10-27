import threading
import time
from typing import Callable, Dict, Optional, Tuple

CHALLENGE_TTL_SECONDS = 300  # 5 minutes


class ChallengeStore:
    """Short-lived, single-use WebAuthn challenges.

    take() removes the challenge whether or not it is still valid, so a challenge
    can be redeemed at most once, and never after its TTL. In-memory and
    per-process: a multi-worker deployment needs a shared store (DB or cache)
    behind the same interface.
    """

    def __init__(self, ttl_seconds: float = CHALLENGE_TTL_SECONDS, clock: Callable[[], float] = time.monotonic):
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._items: Dict[str, Tuple[bytes, float]] = {}

    def put(self, key: str, challenge: bytes) -> None:
        now = self._clock()
        with self._lock:
            # Drop anything already expired so abandoned ceremonies do not accumulate.
            for k in [k for k, (_, exp) in self._items.items() if exp <= now]:
                del self._items[k]
            self._items[key] = (challenge, now + self.ttl_seconds)

    def take(self, key: str) -> Optional[bytes]:
        with self._lock:
            item = self._items.pop(key, None)
        if item is None:
            return None
        challenge, expires_at = item
        return challenge if self._clock() < expires_at else None
