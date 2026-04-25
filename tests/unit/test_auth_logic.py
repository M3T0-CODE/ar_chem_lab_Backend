"""
Unit Tests — Auth Router logic
==============================
All external dependencies (DB, email, OTPService) are mocked so each
route's branching logic is exercised in isolation.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
from fastapi import HTTPException


# ── Helpers ────────────────────────────────────────────────────────────────

def _user(
    username="alice",
    email="alice@example.com",
    hashed_password="hashed",
    is_verified=True,
    disabled=False,
    otp_code=None,
    otp_expires=None,
):
    u = MagicMock()
    u.username = username
    u.email = email
    u.hashed_password = hashed_password
    u.is_verified = is_verified
    u.disabled = disabled
    u.otp_code = otp_code
    u.otp_expires = otp_expires
    return u


# ── Register ───────────────────────────────────────────────────────────────

class TestRegisterLogic:
    """
    Test the register endpoint's guard clauses directly by importing and
    calling the route function with mocked deps.
    """

    @pytest.fixture(autouse=True)
    def _patches(self):
        self.db = MagicMock()
        self.new_user = _user(is_verified=False)

    @patch("app.routes.auth.get_user", return_value=None)
    @patch("app.routes.auth.get_user_by_email", return_value=None)
    @patch("app.routes.auth.create_user")
    @patch("app.routes.auth.OTPService")
    @patch("app.routes.auth.send_otp_email", new_callable=AsyncMock)
    def test_happy_path_returns_message(
        self, mock_email, mock_otp, mock_create, mock_gube, mock_gu
    ):
        from app.routes.auth import register
        from app.schemas.user import RegisterModel
        import asyncio

        mock_create.return_value = self.new_user
        mock_otp.send_registration_otp.return_value = "1234"

        data = RegisterModel(username="alice", email="alice@example.com", password="secret")
        result = asyncio.get_event_loop().run_until_complete(register(data, self.db))
        assert "Registered" in result["message"]

    @patch("app.routes.auth.get_user", return_value=_user())
    def test_duplicate_username_raises_400(self, _):
        from app.routes.auth import register
        from app.schemas.user import RegisterModel
        import asyncio

        data = RegisterModel(username="alice", email="new@example.com", password="secret")
        with pytest.raises(HTTPException) as exc:
            asyncio.get_event_loop().run_until_complete(register(data, MagicMock()))
        assert exc.value.status_code == 400
        assert "Username" in exc.value.detail

    @patch("app.routes.auth.get_user", return_value=None)
    @patch("app.routes.auth.get_user_by_email", return_value=_user())
    def test_duplicate_email_raises_400(self, _gube, _gu):
        from app.routes.auth import register
        from app.schemas.user import RegisterModel
        import asyncio

        data = RegisterModel(username="newuser", email="alice@example.com", password="secret")
        with pytest.raises(HTTPException) as exc:
            asyncio.get_event_loop().run_until_complete(register(data, MagicMock()))
        assert exc.value.status_code == 400
        assert "Email" in exc.value.detail

    @patch("app.routes.auth.get_user", return_value=None)
    @patch("app.routes.auth.get_user_by_email", return_value=None)
    @patch("app.routes.auth.create_user")
    @patch("app.routes.auth.OTPService")
    @patch("app.routes.auth.send_otp_email", new_callable=AsyncMock, side_effect=Exception("SMTP down"))
    def test_email_failure_rolls_back_and_raises_500(
        self, mock_email, mock_otp, mock_create, _gube, _gu
    ):
        from app.routes.auth import register
        from app.schemas.user import RegisterModel
        import asyncio

        mock_create.return_value = self.new_user
        mock_otp.send_registration_otp.return_value = "1234"

        data = RegisterModel(username="alice", email="alice@example.com", password="secret")
        with pytest.raises(HTTPException) as exc:
            asyncio.get_event_loop().run_until_complete(register(data, self.db))
        assert exc.value.status_code == 500
        self.db.delete.assert_called_once_with(self.new_user)
        self.db.commit.assert_called()


# ── Verify Email ───────────────────────────────────────────────────────────

class TestVerifyEmailLogic:
    @patch("app.routes.auth.get_user_by_email", return_value=None)
    def test_unknown_email_raises_404(self, _):
        from app.routes.auth import verify_email
        from app.schemas.user import VerifyEmailModel

        data = VerifyEmailModel(email="nobody@x.com", code="1234")
        with pytest.raises(HTTPException) as exc:
            verify_email(data, MagicMock())
        assert exc.value.status_code == 404

    @patch("app.routes.auth.OTPService")
    @patch("app.routes.auth.get_user_by_email")
    def test_invalid_otp_raises_400(self, mock_gube, mock_otp):
        from app.routes.auth import verify_email
        from app.schemas.user import VerifyEmailModel

        mock_gube.return_value = _user(is_verified=False)
        mock_otp.verify.return_value = False

        data = VerifyEmailModel(email="alice@example.com", code="wrong")
        with pytest.raises(HTTPException) as exc:
            verify_email(data, MagicMock())
        assert exc.value.status_code == 400

    @patch("app.routes.auth.OTPService")
    @patch("app.routes.auth.get_user_by_email")
    def test_valid_otp_marks_verified(self, mock_gube, mock_otp):
        from app.routes.auth import verify_email
        from app.schemas.user import VerifyEmailModel

        user = _user(is_verified=False)
        mock_gube.return_value = user
        mock_otp.verify.return_value = True

        data = VerifyEmailModel(email="alice@example.com", code="1234")
        result = verify_email(data, MagicMock())
        assert user.is_verified is True
        assert "verified" in result["message"].lower()


# ── Login ──────────────────────────────────────────────────────────────────

class TestLoginLogic:
    @patch("app.routes.auth.get_user_by_email", return_value=None)
    def test_unknown_user_raises_401(self, _):
        from app.routes.auth import login
        from app.schemas.user import LoginModel

        data = LoginModel(email="ghost@x.com", password="pw")
        with pytest.raises(HTTPException) as exc:
            login(data, MagicMock())
        assert exc.value.status_code == 401

    @patch("app.routes.auth.verify_password", return_value=False)
    @patch("app.routes.auth.get_user_by_email")
    def test_wrong_password_raises_401(self, mock_gube, _):
        from app.routes.auth import login
        from app.schemas.user import LoginModel

        mock_gube.return_value = _user()
        data = LoginModel(email="alice@example.com", password="bad")
        with pytest.raises(HTTPException) as exc:
            login(data, MagicMock())
        assert exc.value.status_code == 401

    @patch("app.routes.auth.verify_password", return_value=True)
    @patch("app.routes.auth.get_user_by_email")
    def test_unverified_user_raises_403(self, mock_gube, _):
        from app.routes.auth import login
        from app.schemas.user import LoginModel

        mock_gube.return_value = _user(is_verified=False)
        data = LoginModel(email="alice@example.com", password="pw")
        with pytest.raises(HTTPException) as exc:
            login(data, MagicMock())
        assert exc.value.status_code == 403
        assert "verified" in exc.value.detail.lower()

    @patch("app.routes.auth.verify_password", return_value=True)
    @patch("app.routes.auth.get_user_by_email")
    def test_disabled_user_raises_403(self, mock_gube, _):
        from app.routes.auth import login
        from app.schemas.user import LoginModel

        mock_gube.return_value = _user(disabled=True)
        data = LoginModel(email="alice@example.com", password="pw")
        with pytest.raises(HTTPException) as exc:
            login(data, MagicMock())
        assert exc.value.status_code == 403
        assert "disabled" in exc.value.detail.lower()

    @patch("app.routes.auth.create_access_token", return_value="access")
    @patch("app.routes.auth.create_refresh_token", return_value="refresh")
    @patch("app.routes.auth.verify_password", return_value=True)
    @patch("app.routes.auth.get_user_by_email")
    def test_valid_login_returns_tokens(self, mock_gube, _vp, _crt, _cat):
        from app.routes.auth import login
        from app.schemas.user import LoginModel

        mock_gube.return_value = _user()
        data = LoginModel(email="alice@example.com", password="pw")
        result = login(data, MagicMock())
        assert result["access_token"] == "access"
        assert result["refresh_token"] == "refresh"
        assert result["token_type"] == "bearer"


# ── Reset Password ─────────────────────────────────────────────────────────

class TestResetPasswordLogic:
    @patch("app.routes.auth.get_user_by_email", return_value=None)
    def test_unknown_user_raises_404(self, _):
        from app.routes.auth import reset_password
        from app.schemas.user import ResetPasswordModel

        data = ResetPasswordModel(email="nobody@x.com", code="1234", new_password="newpw")
        with pytest.raises(HTTPException) as exc:
            reset_password(data, MagicMock())
        assert exc.value.status_code == 404

    @patch("app.routes.auth.OTPService")
    @patch("app.routes.auth.get_user_by_email")
    def test_invalid_otp_raises_400(self, mock_gube, mock_otp):
        from app.routes.auth import reset_password
        from app.schemas.user import ResetPasswordModel

        mock_gube.return_value = _user()
        mock_otp.verify.return_value = False

        data = ResetPasswordModel(email="alice@example.com", code="bad", new_password="newpw")
        with pytest.raises(HTTPException) as exc:
            reset_password(data, MagicMock())
        assert exc.value.status_code == 400

    @patch("app.routes.auth.OTPService")
    @patch("app.routes.auth.update_password")
    @patch("app.routes.auth.get_user_by_email")
    def test_valid_reset_calls_update_password(self, mock_gube, mock_up, mock_otp):
        from app.routes.auth import reset_password
        from app.schemas.user import ResetPasswordModel

        user = _user()
        mock_gube.return_value = user
        mock_otp.verify.return_value = True

        data = ResetPasswordModel(email="alice@example.com", code="1234", new_password="newpw")
        result = reset_password(data, MagicMock())
        mock_up.assert_called_once()
        mock_otp.clear.assert_called_once()
        assert "reset" in result["message"].lower()
