"""
Unit Tests — OTPService
=======================
Pure logic tests; no database, no HTTP.
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
from app.services.otp import OTPService, OTP_EXPIRE_MINUTES


# ── Helpers ────────────────────────────────────────────────────────────────

def make_user(otp_code=None, otp_expires=None):
    user = MagicMock()
    user.otp_code = otp_code
    user.otp_expires = otp_expires
    user.is_verified = True
    return user


def make_db():
    db = MagicMock()
    db.commit = MagicMock()
    return db


# ── OTPService.generate ────────────────────────────────────────────────────

class TestGenerate:
    def test_returns_string(self):
        assert isinstance(OTPService.generate(), str)

    def test_four_digits(self):
        for _ in range(50):
            code = OTPService.generate()
            assert len(code) == 4
            assert code.isdigit()

    def test_value_in_range(self):
        for _ in range(100):
            assert 1000 <= int(OTPService.generate()) <= 9999

    def test_values_are_random(self):
        codes = {OTPService.generate() for _ in range(20)}
        # With 9000 possible values, 20 draws should not all be identical
        assert len(codes) > 1


# ── OTPService.send_registration_otp ──────────────────────────────────────

class TestSendRegistrationOtp:
    def test_sets_otp_code(self):
        db, user = make_db(), make_user()
        code = OTPService.send_registration_otp(db, user)
        assert user.otp_code == code

    def test_sets_expiry(self):
        db, user = make_db(), make_user()
        before = datetime.utcnow()
        OTPService.send_registration_otp(db, user)
        after = datetime.utcnow()
        expected_min = before + timedelta(minutes=OTP_EXPIRE_MINUTES) - timedelta(seconds=1)
        expected_max = after + timedelta(minutes=OTP_EXPIRE_MINUTES) + timedelta(seconds=1)
        assert expected_min <= user.otp_expires <= expected_max

    def test_marks_user_unverified(self):
        db, user = make_db(), make_user()
        user.is_verified = True
        OTPService.send_registration_otp(db, user)
        assert user.is_verified is False

    def test_commits(self):
        db, user = make_db(), make_user()
        OTPService.send_registration_otp(db, user)
        db.commit.assert_called_once()

    def test_returns_4_digit_code(self):
        db, user = make_db(), make_user()
        code = OTPService.send_registration_otp(db, user)
        assert len(code) == 4 and code.isdigit()


# ── OTPService.send_reset_otp ──────────────────────────────────────────────

class TestSendResetOtp:
    def test_sets_otp_code(self):
        db, user = make_db(), make_user()
        code = OTPService.send_reset_otp(db, user)
        assert user.otp_code == code

    def test_does_not_change_is_verified(self):
        db, user = make_db(), make_user()
        user.is_verified = True
        OTPService.send_reset_otp(db, user)
        assert user.is_verified is True   # untouched

    def test_sets_expiry(self):
        db, user = make_db(), make_user()
        OTPService.send_reset_otp(db, user)
        assert user.otp_expires is not None

    def test_commits(self):
        db, user = make_db(), make_user()
        OTPService.send_reset_otp(db, user)
        db.commit.assert_called_once()


# ── OTPService.verify ──────────────────────────────────────────────────────

class TestVerify:
    def test_valid_code_returns_true(self):
        user = make_user(
            otp_code="5678",
            otp_expires=datetime.utcnow() + timedelta(minutes=5),
        )
        assert OTPService.verify(user, "5678") is True

    def test_wrong_code_returns_false(self):
        user = make_user(
            otp_code="5678",
            otp_expires=datetime.utcnow() + timedelta(minutes=5),
        )
        assert OTPService.verify(user, "0000") is False

    def test_expired_code_returns_false(self):
        user = make_user(
            otp_code="5678",
            otp_expires=datetime.utcnow() - timedelta(seconds=1),
        )
        assert OTPService.verify(user, "5678") is False

    def test_no_otp_code_returns_false(self):
        user = make_user(otp_code=None, otp_expires=datetime.utcnow() + timedelta(minutes=5))
        assert OTPService.verify(user, "1234") is False

    def test_no_expiry_returns_false(self):
        user = make_user(otp_code="1234", otp_expires=None)
        assert OTPService.verify(user, "1234") is False

    def test_exactly_at_expiry_returns_true(self):
        """
        verify() uses strict `>` so when utcnow() == otp_expires the code is
        NOT yet expired and should still be accepted.
        """
        now = datetime.utcnow()
        user = make_user(otp_code="1234", otp_expires=now)
        with patch("app.services.otp.datetime") as mock_dt:
            mock_dt.utcnow.return_value = now
            result = OTPService.verify(user, "1234")
        assert result is True

    def test_one_second_past_expiry_returns_false(self):
        """A code 1 second past its expiry must be rejected."""
        expires = datetime.utcnow()
        user = make_user(otp_code="1234", otp_expires=expires)
        with patch("app.services.otp.datetime") as mock_dt:
            mock_dt.utcnow.return_value = expires + timedelta(seconds=1)
            result = OTPService.verify(user, "1234")
        assert result is False


# ── OTPService.clear ───────────────────────────────────────────────────────

class TestClear:
    def test_clears_otp_code(self):
        db, user = make_db(), make_user(otp_code="1234", otp_expires=datetime.utcnow())
        OTPService.clear(db, user)
        assert user.otp_code is None

    def test_clears_expiry(self):
        db, user = make_db(), make_user(otp_code="1234", otp_expires=datetime.utcnow())
        OTPService.clear(db, user)
        assert user.otp_expires is None

    def test_commits(self):
        db, user = make_db(), make_user()
        OTPService.clear(db, user)
        db.commit.assert_called_once()
