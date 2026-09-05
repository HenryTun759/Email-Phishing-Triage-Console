import jwt
from app.auth import hash_password, verify_password, create_access_token
from app.models import User
from app.config import settings

def test_password_hash_is_not_plaintext():
    raw = "Correct-Horse-Battery-Staple-123!"
    hashed = hash_password(raw)
    assert hashed != raw
    assert verify_password(raw, hashed)
    assert not verify_password("wrong-password", hashed)

def test_access_token_contains_expiration():
    user = User(id=7, username="tester", role="analyst", is_active=True)
    token = create_access_token(user)
    claims = jwt.decode(token, settings.jwt_secret.get_secret_value(), algorithms=[settings.jwt_algorithm])
    assert claims["sub"] == "7"
    assert "exp" in claims
