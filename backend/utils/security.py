from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Header
from jose import jwt, JWTError
import bcrypt
from config import JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRY_MINUTES


# ---------------------------------------------------------------------------
# Password hashing (bcrypt — for admin passwords only)
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# ---------------------------------------------------------------------------
# OTP encoding / decoding (JWT-based — no hashing, reversible)
# ---------------------------------------------------------------------------
def encode_otp(otp: str) -> str:
    """Encode OTP into a JWT so it can be decoded back for comparison."""
    payload = {"otp": otp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_otp(encoded: str) -> str:
    """Decode the JWT to retrieve the original OTP."""
    try:
        payload = jwt.decode(encoded, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("otp", "")
    except JWTError:
        return ""


# ---------------------------------------------------------------------------
# JWT helpers (for auth tokens)
# ---------------------------------------------------------------------------
def create_jwt(payload: dict) -> str:
    data = payload.copy()
    data["exp"] = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY_MINUTES)
    data["iat"] = datetime.now(timezone.utc)
    return jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ---------------------------------------------------------------------------
# Bearer token extraction
# ---------------------------------------------------------------------------
def extract_bearer_token(authorization: str = Header(...)) -> str:
    """Extract and validate Bearer token from Authorization header."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header is required")
    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header format. Use: Bearer <token>",
        )
    token = parts[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Token is empty")
    return token
