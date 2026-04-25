"""
Integration Tests — OTPService with real SQLite session
=======================================================
Each test gets a fresh User row that is explicitly deleted in teardown.
This is simpler and more reliable than savepoint tricks.
"""
import pytest
import uuid
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.services.otp import OTPService, OTP_EXPIRE_MINUTES


# ── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def engine_and_tables():
    from app.database.session import Base
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)


@pytest.fixture(scope="module")
def session(engine_and_tables):
    """One session shared across all tests in the module."""
    Session = sessionmaker(bind=engine_and_tables)
    sess = Session()
    yield sess
    sess.close()


@pytest.fixture
def user(session):
    """
    Create a unique user before each test and delete it after.
    Using uuid avoids UNIQUE constraint collisions between tests.
    """
    from app.models.user import User
    uid = uuid.uuid4().hex[:8]
    u = User(
        username=f"integuser_{uid}",
        email=f"integ_{uid}@example.com",
        hashed_password="fakehash_not_needed_for_otp_tests",
        is_verified=False,
    )
    session.add(u)
    session.commit()
    session.refresh(u)

    yield u

    # Teardown: clean up this user so nothing leaks
    session.delete(u)
    session.commit()


# ── Tests ──────────────────────────────────────────────────────────────────

class TestOtpServiceIntegration:
    def test_registration_otp_persisted(self, session, user):
        code = OTPService.send_registration_otp(session, user)
        session.refresh(user)
        assert user.otp_code == code
        assert user.otp_expires is not None
        assert user.is_verified is False

    def test_registration_otp_expiry_window(self, session, user):
        before = datetime.utcnow()
        OTPService.send_registration_otp(session, user)
        after = datetime.utcnow()
        session.refresh(user)
        assert before + timedelta(minutes=OTP_EXPIRE_MINUTES - 1) < user.otp_expires
        assert user.otp_expires < after + timedelta(minutes=OTP_EXPIRE_MINUTES + 1)

    def test_verify_correct_code(self, session, user):
        code = OTPService.send_registration_otp(session, user)
        assert OTPService.verify(user, code) is True

    def test_verify_wrong_code(self, session, user):
        OTPService.send_registration_otp(session, user)
        assert OTPService.verify(user, "0000") is False

    def test_verify_expired_code(self, session, user):
        OTPService.send_registration_otp(session, user)
        user.otp_expires = datetime.utcnow() - timedelta(seconds=1)
        session.commit()
        assert OTPService.verify(user, user.otp_code) is False

    def test_clear_removes_otp(self, session, user):
        OTPService.send_registration_otp(session, user)
        OTPService.clear(session, user)
        session.refresh(user)
        assert user.otp_code is None
        assert user.otp_expires is None

    def test_verify_after_clear_returns_false(self, session, user):
        code = OTPService.send_registration_otp(session, user)
        OTPService.clear(session, user)
        assert OTPService.verify(user, code) is False

    def test_reset_otp_does_not_touch_is_verified(self, session, user):
        user.is_verified = True
        session.commit()
        OTPService.send_reset_otp(session, user)
        session.refresh(user)
        assert user.is_verified is True

    def test_second_registration_otp_overwrites_first(self, session, user):
        first = OTPService.send_registration_otp(session, user)
        second = OTPService.send_registration_otp(session, user)
        session.refresh(user)
        assert user.otp_code == second
        assert OTPService.verify(user, first) == (first == second)