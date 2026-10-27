import threading

from fastapi import HTTPException
from sqlalchemy.orm import Session

from src.auth.tokens.service import issue_refresh_token_family, rotate_refresh_token
from src.models.token_store import RefreshTokenStore
from src.models.user import User
from tests.conftest import TestingSessionLocal, test_engine


class _RaceSession(Session):
    """Holds each refresh at the user lookup, after the reuse checks but before the
    token is consumed, until both concurrent refreshes have reached that point."""

    barrier: threading.Barrier = None

    def query(self, *entities, **kwargs):
        if entities and entities[0] is User and self.barrier is not None:
            try:
                self.barrier.wait(timeout=5)
            except threading.BrokenBarrierError:
                pass
        return super().query(*entities, **kwargs)


def test_concurrent_refresh_with_same_token_is_treated_as_reuse(db_session):
    user = User(username="race_user", email="race_user@example.com", role="analyst")
    db_session.add(user)
    db_session.commit()
    raw_token = issue_refresh_token_family(db_session, user.id)

    barrier = threading.Barrier(2)
    results, errors = [], []

    def refresh():
        session = _RaceSession(bind=test_engine, autoflush=False)
        session.barrier = barrier
        try:
            results.append(rotate_refresh_token(session, raw_token, client_ip="10.0.0.9"))
        except HTTPException as exc:
            errors.append(exc.status_code)
        finally:
            session.close()

    threads = [threading.Thread(target=refresh) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    # Exactly one refresh may win; the other is reuse and must revoke the family.
    assert len(results) == 1, f"both concurrent refreshes succeeded: {results}"
    assert errors == [403]

    check = TestingSessionLocal()
    try:
        family = check.query(RefreshTokenStore).filter(RefreshTokenStore.user_id == user.id).all()
        assert family and all(t.is_revoked for t in family), "token family must be fully revoked"
    finally:
        check.close()
