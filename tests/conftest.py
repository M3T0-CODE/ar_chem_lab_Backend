"""
Shared fixtures for unit, integration, and API tests.
"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# In-memory SQLite engine for integration / API tests
# ---------------------------------------------------------------------------
TEST_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    TEST_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ---------------------------------------------------------------------------
# App import (delayed so env vars can be patched first)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def patch_settings():
    """Patch settings before the app is imported."""
    with patch.dict(
        "os.environ",
        {
            "SECRET_KEY": "test-secret-key-that-is-long-enough",
            "ALGORITHM": "HS256",
            "ACCESS_TOKEN_EXPIRE_MINUTES": "30",
            "REFRESH_TOKEN_EXPIRE_DAYS": "7",
        },
    ):
        yield


@pytest.fixture(scope="session")
def app(patch_settings):
    from app.database.session import Base
    from app.main import app as fastapi_app
    from app.database.session import get_db

    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    fastapi_app.dependency_overrides[get_db] = override_get_db
    yield fastapi_app
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    """Fresh DB session that rolls back after each test."""
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(app):
    return TestClient(app)


# ---------------------------------------------------------------------------
# Model helpers
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_user():
    user = MagicMock()
    user.id = 1
    user.username = "testuser"
    user.email = "test@example.com"
    user.hashed_password = "hashed_pw"
    user.is_verified = True
    user.disabled = False
    user.otp_code = None
    user.otp_expires = None
    return user


@pytest.fixture
def valid_otp_user(mock_user):
    mock_user.otp_code = "1234"
    mock_user.otp_expires = datetime.utcnow() + timedelta(minutes=5)
    return mock_user


@pytest.fixture
def expired_otp_user(mock_user):
    mock_user.otp_code = "1234"
    mock_user.otp_expires = datetime.utcnow() - timedelta(minutes=1)
    return mock_user