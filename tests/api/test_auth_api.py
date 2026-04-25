"""
API Tests — Full HTTP round-trips via FastAPI TestClient
========================================================
Email sending is always mocked; everything else hits the real
SQLite-backed app (via the `client` fixture from conftest.py).

Each test class that needs a pre-registered user generates unique
credentials via uuid so parallel/sequential runs never collide.
"""
import uuid
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient


# ── Helpers ────────────────────────────────────────────────────────────────

REGISTER_URL = "/register"
VERIFY_URL   = "/verify-email"
LOGIN_URL    = "/login"
REFRESH_URL  = "/refresh"
PROFILE_URL  = "/profile"
FORGOT_URL   = "/forgot-password"
RESET_URL    = "/reset-password"

MOCK_EMAIL = patch("app.routes.auth.send_otp_email", new_callable=AsyncMock)


def unique_user(prefix="user"):
    """Return (username, email) that are unique per call."""
    uid = uuid.uuid4().hex[:8]
    return f"{prefix}_{uid}", f"{prefix}_{uid}@example.com"


def register_and_verify(client, username, email, password="Secret123"):
    """Register + verify a user. Returns the OTP code used."""
    with MOCK_EMAIL as mock_mail:
        resp = client.post(REGISTER_URL, json={"username": username, "email": email, "password": password})
        assert resp.status_code == 200, resp.text
        code = mock_mail.call_args[0][1]   # 2nd positional arg to send_otp_email

    resp = client.post(VERIFY_URL, json={"email": email, "code": code})
    assert resp.status_code == 200, resp.text
    return code


def do_login(client, email, password="Secret123"):
    resp = client.post(LOGIN_URL, json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


# ── POST /register ─────────────────────────────────────────────────────────

class TestRegisterAPI:
    def test_successful_registration(self, client):
        username, email = unique_user("reg")
        with MOCK_EMAIL:
            resp = client.post(REGISTER_URL, json={"username": username, "email": email, "password": "Secure1!"})
        assert resp.status_code == 200
        assert "Registered" in resp.json()["message"]

    def test_duplicate_username_returns_400(self, client):
        username, email = unique_user("dupname")
        with MOCK_EMAIL:
            client.post(REGISTER_URL, json={"username": username, "email": email, "password": "pw"})
        with MOCK_EMAIL:
            resp = client.post(REGISTER_URL, json={"username": username, "email": f"other_{uuid.uuid4().hex[:6]}@example.com", "password": "pw"})
        assert resp.status_code == 400
        assert "Username" in resp.json()["detail"]

    def test_duplicate_email_returns_400(self, client):
        username, email = unique_user("dupemail")
        with MOCK_EMAIL:
            client.post(REGISTER_URL, json={"username": username, "email": email, "password": "pw"})
        with MOCK_EMAIL:
            resp = client.post(REGISTER_URL, json={"username": f"other_{uuid.uuid4().hex[:6]}", "email": email, "password": "pw"})
        assert resp.status_code == 400
        assert "Email" in resp.json()["detail"]

    def test_email_failure_returns_500(self, client):
        username, email = unique_user("failreg")
        with patch("app.routes.auth.send_otp_email", new_callable=AsyncMock, side_effect=Exception("SMTP")):
            resp = client.post(REGISTER_URL, json={"username": username, "email": email, "password": "pw"})
        assert resp.status_code == 500

    def test_missing_fields_returns_422(self, client):
        resp = client.post(REGISTER_URL, json={"username": "onlyname"})
        assert resp.status_code == 422


# ── POST /verify-email ─────────────────────────────────────────────────────

class TestVerifyEmailAPI:
    def test_valid_otp_verifies_user(self, client):
        username, email = unique_user("veremail")
        with MOCK_EMAIL as mock_mail:
            client.post(REGISTER_URL, json={"username": username, "email": email, "password": "pw"})
            code = mock_mail.call_args[0][1]
        resp = client.post(VERIFY_URL, json={"email": email, "code": code})
        assert resp.status_code == 200
        assert "verified" in resp.json()["message"].lower()

    def test_wrong_otp_returns_400(self, client):
        username, email = unique_user("wrongotp")
        with MOCK_EMAIL:
            client.post(REGISTER_URL, json={"username": username, "email": email, "password": "pw"})
        resp = client.post(VERIFY_URL, json={"email": email, "code": "0000"})
        assert resp.status_code == 400

    def test_unknown_email_returns_404(self, client):
        resp = client.post(VERIFY_URL, json={"email": "ghost@x.com", "code": "1234"})
        assert resp.status_code == 404


# ── POST /login ────────────────────────────────────────────────────────────

class TestLoginAPI:
    @pytest.fixture(autouse=True)
    def _setup_user(self, client):
        self.username, self.email = unique_user("login")
        register_and_verify(client, self.username, self.email, "Secure1!")

    def test_valid_login_returns_tokens(self, client):
        resp = client.post(LOGIN_URL, json={"email": self.email, "password": "Secure1!"})
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert "refresh_token" in body
        assert body["token_type"] == "bearer"

    def test_wrong_password_returns_401(self, client):
        resp = client.post(LOGIN_URL, json={"email": self.email, "password": "wrong"})
        assert resp.status_code == 401

    def test_unknown_email_returns_401(self, client):
        resp = client.post(LOGIN_URL, json={"email": "nobody@x.com", "password": "pw"})
        assert resp.status_code == 401

    def test_unverified_user_returns_403(self, client):
        username, email = unique_user("unver")
        with MOCK_EMAIL:
            client.post(REGISTER_URL, json={"username": username, "email": email, "password": "pw"})
        resp = client.post(LOGIN_URL, json={"email": email, "password": "pw"})
        assert resp.status_code == 403
        assert "verified" in resp.json()["detail"].lower()


# ── POST /refresh ──────────────────────────────────────────────────────────

class TestRefreshTokenAPI:
    @pytest.fixture(autouse=True)
    def _setup(self, client):
        username, email = unique_user("refresh")
        register_and_verify(client, username, email, "Secure1!")
        self.tokens = do_login(client, email, "Secure1!")

    def test_valid_refresh_returns_new_access_token(self, client):
        resp = client.post(REFRESH_URL, json={"refresh_token": self.tokens["refresh_token"]})
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_access_token_as_refresh_returns_401(self, client):
        resp = client.post(REFRESH_URL, json={"refresh_token": self.tokens["access_token"]})
        assert resp.status_code == 401

    def test_garbage_token_returns_401(self, client):
        resp = client.post(REFRESH_URL, json={"refresh_token": "not.a.jwt"})
        assert resp.status_code == 401


# ── GET /profile ───────────────────────────────────────────────────────────

class TestProfileAPI:
    @pytest.fixture(autouse=True)
    def _setup(self, client):
        self.username, self.email = unique_user("prof")
        register_and_verify(client, self.username, self.email, "Secure1!")
        tokens = do_login(client, self.email, "Secure1!")
        self.auth_headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    def test_authenticated_returns_profile(self, client):
        resp = client.get(PROFILE_URL, headers=self.auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["email"] == self.email
        assert body["username"] == self.username

    def test_no_token_returns_401(self, client):
        resp = client.get(PROFILE_URL)
        assert resp.status_code == 401

    def test_invalid_token_returns_401(self, client):
        resp = client.get(PROFILE_URL, headers={"Authorization": "Bearer bad.token.here"})
        assert resp.status_code == 401


# ── POST /forgot-password ──────────────────────────────────────────────────

class TestForgotPasswordAPI:
    @pytest.fixture(autouse=True)
    def _setup(self, client):
        self.username, self.email = unique_user("fp")
        register_and_verify(client, self.username, self.email, "Secure1!")

    def test_known_email_sends_otp(self, client):
        with MOCK_EMAIL as mock_mail:
            resp = client.post(FORGOT_URL, json={"email": self.email})
        assert resp.status_code == 200
        mock_mail.assert_called_once()
        assert "reset" in resp.json()["message"].lower()

    def test_unknown_email_returns_404(self, client):
        resp = client.post(FORGOT_URL, json={"email": "ghost@x.com"})
        assert resp.status_code == 404


# ── POST /reset-password ───────────────────────────────────────────────────

class TestResetPasswordAPI:
    @pytest.fixture(autouse=True)
    def _setup(self, client):
        self.username, self.email = unique_user("rp")
        register_and_verify(client, self.username, self.email, "OldPass1!")

    def test_full_reset_flow(self, client):
        # 1. Request reset OTP
        with MOCK_EMAIL as mock_mail:
            resp = client.post(FORGOT_URL, json={"email": self.email})
            assert resp.status_code == 200
            reset_code = mock_mail.call_args[0][1]

        # 2. Reset password
        resp = client.post(RESET_URL, json={"email": self.email, "code": reset_code, "new_password": "NewPass1!"})
        assert resp.status_code == 200
        assert "reset" in resp.json()["message"].lower()

        # 3. Old password no longer works
        resp = client.post(LOGIN_URL, json={"email": self.email, "password": "OldPass1!"})
        assert resp.status_code == 401

        # 4. New password works
        resp = client.post(LOGIN_URL, json={"email": self.email, "password": "NewPass1!"})
        assert resp.status_code == 200

    def test_wrong_otp_returns_400(self, client):
        with MOCK_EMAIL:
            client.post(FORGOT_URL, json={"email": self.email})
        resp = client.post(RESET_URL, json={"email": self.email, "code": "0000", "new_password": "NewPass1!"})
        assert resp.status_code == 400

    def test_unknown_user_returns_404(self, client):
        resp = client.post(RESET_URL, json={"email": "nobody@x.com", "code": "1234", "new_password": "NewPass1!"})
        assert resp.status_code == 404

    def test_otp_cannot_be_reused(self, client):
        with MOCK_EMAIL as mock_mail:
            client.post(FORGOT_URL, json={"email": self.email})
            code = mock_mail.call_args[0][1]

        # First use — success
        client.post(RESET_URL, json={"email": self.email, "code": code, "new_password": "NewPass2!"})

        # Second use — OTP was cleared, must fail
        resp = client.post(RESET_URL, json={"email": self.email, "code": code, "new_password": "AnotherPass!"})
        assert resp.status_code == 400