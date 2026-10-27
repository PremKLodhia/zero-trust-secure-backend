import pytest

from src.auth.webauthn import service
from src.auth.webauthn.challenge_store import CHALLENGE_TTL_SECONDS, ChallengeStore


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(service, "challenge_store", ChallengeStore(clock=fake))
    return fake


def test_ttl_is_five_minutes():
    assert CHALLENGE_TTL_SECONDS == 300


def test_challenge_is_single_use():
    store = ChallengeStore(clock=FakeClock())
    store.put("register:u1", b"challenge")
    assert store.take("register:u1") == b"challenge"
    assert store.take("register:u1") is None


def test_expired_challenge_is_rejected():
    clock = FakeClock()
    store = ChallengeStore(clock=clock)
    store.put("register:u1", b"challenge")
    clock.now += CHALLENGE_TTL_SECONDS + 1
    assert store.take("register:u1") is None


def test_expired_registration_challenge_fails_verification(clock):
    service.get_registration_options("u1", "alice", "Alice")
    clock.now += CHALLENGE_TTL_SECONDS + 1
    with pytest.raises(ValueError, match="No active registration challenge"):
        service.verify_registration("u1", "{}")


def test_expired_authentication_challenge_fails_verification(clock):
    service.challenge_store.put("authenticate:u1", b"challenge")
    clock.now += CHALLENGE_TTL_SECONDS + 1
    with pytest.raises(ValueError, match="No active authentication challenge"):
        service.verify_authentication("u1", "AAAA", "AAAA", 0, "{}")


def test_live_challenge_is_consumed_by_the_first_attempt(clock):
    service.get_registration_options("u1", "alice", "Alice")
    clock.now += CHALLENGE_TTL_SECONDS - 1
    # The challenge is found (the bogus credential fails later, during parsing)...
    with pytest.raises(Exception) as first:
        service.verify_registration("u1", "{}")
    assert "No active registration challenge" not in str(first.value)
    # ...and cannot be replayed.
    with pytest.raises(ValueError, match="No active registration challenge"):
        service.verify_registration("u1", "{}")


def test_registration_challenge_cannot_be_used_to_authenticate(clock):
    service.get_registration_options("u1", "alice", "Alice")
    with pytest.raises(ValueError, match="No active authentication challenge"):
        service.verify_authentication("u1", "AAAA", "AAAA", 0, "{}")
