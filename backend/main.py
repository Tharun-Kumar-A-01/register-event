import os
import re
import random
import smtplib
import logging
from datetime import datetime, date, time, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks
from pydantic import BaseModel, EmailStr, field_validator
from sqlmodel import SQLModel, Field, create_engine, Session, select
from sqlalchemy import Column, DateTime
from jose import jwt, JWTError
import bcrypt
from fastapi.middleware.cors import CORSMiddleware

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")
JWT_SECRET = os.environ.get("JWT_SECRET")
GMAIL_USER = os.environ.get("GMAIL_USER")
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD")

if not all([DATABASE_URL, JWT_SECRET, GMAIL_USER, GMAIL_APP_PASSWORD]):
    raise RuntimeError(
        "Missing required environment variables. "
        "Set DATABASE_URL, JWT_SECRET, GMAIL_USER, GMAIL_APP_PASSWORD in .env"
    )

JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = 30
OTP_EXPIRY_MINUTES = 10
POST_COOLDOWN_MINUTES = 30
OTP_LENGTH = 6
MAX_STRING_LENGTH = 500
MAX_DESCRIPTION_LENGTH = 2000
MAX_URL_LENGTH = 2048

# ---------------------------------------------------------------------------
# Logging — console output for every event
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("tamilnadu_events")

# ---------------------------------------------------------------------------
# Database engine
# ---------------------------------------------------------------------------
engine = create_engine(DATABASE_URL, echo=False)


def get_session():
    with Session(engine) as session:
        yield session


# ---------------------------------------------------------------------------
# Password / OTP hashing (using bcrypt directly)
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def hash_otp(otp: str) -> str:
    return bcrypt.hashpw(otp.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_otp_hash(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# ---------------------------------------------------------------------------
# JWT helpers
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
# Email helper — runs in background thread (non-blocking)
# ---------------------------------------------------------------------------
def _send_otp_email_sync(recipient: str, otp: str) -> None:
    """Synchronous email sending — called from a background task."""
    try:
        msg = MIMEMultipart()
        msg["From"] = GMAIL_USER
        msg["To"] = recipient
        msg["Subject"] = "Your OTP for Event Submission"

        body = (
            f"Your OTP for event submission is: {otp}\n\n"
            f"This OTP is valid for {OTP_EXPIRY_MINUTES} minutes.\n"
            "If you did not request this, please ignore this email."
        )
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_USER, recipient, msg.as_string())

        logger.info("OTP email sent successfully to %s", recipient)
    except Exception as e:
        logger.error("Failed to send OTP email to %s: %s", recipient, e)


# ---------------------------------------------------------------------------
# Timezone helper
# ---------------------------------------------------------------------------
def to_utc(dt: datetime) -> datetime:
    """
    Convert a datetime to UTC.
    - If naive (no tzinfo): assume it is in the server's local timezone and
      convert to UTC. This fixes the mismatch when the DB returns naive
      timestamps in local time (e.g. IST).
    - If aware: convert to UTC directly.
    """
    if dt.tzinfo is None:
        # Treat naive datetime as local time, then convert to UTC
        local_dt = dt.astimezone()  # attach local tz
        return local_dt.astimezone(timezone.utc)
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------
def sanitize_string(value: str, max_length: int = MAX_STRING_LENGTH) -> str:
    """Strip whitespace and limit length."""
    if not isinstance(value, str):
        raise ValueError("Expected a string value")
    value = value.strip()
    if len(value) == 0:
        raise ValueError("Value cannot be empty")
    if len(value) > max_length:
        raise ValueError(f"Value exceeds maximum length of {max_length}")
    return value


def validate_url(value: str) -> str:
    """Basic URL format validation."""
    value = sanitize_string(value, max_length=MAX_URL_LENGTH)
    url_pattern = re.compile(
        r"^https?://"
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}"
        r"(?:/[^\s]*)?$"
    )
    if not url_pattern.match(value):
        raise ValueError("Invalid URL format. Must start with http:// or https://")
    return value


def extract_bearer_token(authorization: str = Header(...)) -> str:
    """Extract and validate Bearer token from Authorization header."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header is required")
    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=401, detail="Invalid Authorization header format. Use: Bearer <token>"
        )
    token = parts[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Token is empty")
    return token


# ---------------------------------------------------------------------------
# Database models
# ---------------------------------------------------------------------------
class Event(SQLModel, table=True):
    __tablename__ = "events"

    id: Optional[int] = Field(default=None, primary_key=True)
    eventName: str
    eventDescription: str
    eventDate: date
    eventTime: time
    eventVenue: str
    eventLink: str
    location: str
    communityName: str
    email: str
    approved: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_column=Column(DateTime(timezone=True)))


class TempEvent(SQLModel, table=True):
    __tablename__ = "temp_events"

    id: Optional[int] = Field(default=None, primary_key=True)
    eventName: str
    eventDescription: str
    eventDate: date
    eventTime: time
    eventVenue: str
    eventLink: str
    location: str
    communityName: str
    email: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_column=Column(DateTime(timezone=True)))


class OTPRecord(SQLModel, table=True):
    __tablename__ = "otp_records"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str
    otp_hash: str
    temp_event_id: int = Field(foreign_key="temp_events.id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_column=Column(DateTime(timezone=True)))


class RecentPost(SQLModel, table=True):
    __tablename__ = "recent_posts"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_column=Column(DateTime(timezone=True)))


class Admin(SQLModel, table=True):
    __tablename__ = "admins"

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    hashed_password: str
    token: Optional[str] = Field(default=None)


# ---------------------------------------------------------------------------
# Pydantic request/response schemas
# ---------------------------------------------------------------------------
class EventCreate(BaseModel):
    eventName: str
    eventDescription: str
    eventDate: date
    eventTime: time
    eventVenue: str
    eventLink: str
    location: str
    communityName: str
    email: EmailStr

    @field_validator("eventName", "eventVenue", "location", "communityName")
    @classmethod
    def validate_string_fields(cls, v: str) -> str:
        return sanitize_string(v)

    @field_validator("eventDescription")
    @classmethod
    def validate_description(cls, v: str) -> str:
        return sanitize_string(v, max_length=MAX_DESCRIPTION_LENGTH)

    @field_validator("eventLink")
    @classmethod
    def validate_event_link(cls, v: str) -> str:
        return validate_url(v)

    @field_validator("email")
    @classmethod
    def validate_email_field(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("eventDate")
    @classmethod
    def validate_event_date(cls, v: date) -> date:
        if v < date.today():
            raise ValueError("Event date cannot be in the past")
        return v


class EventPublicResponse(BaseModel):
    id: int
    eventName: str
    eventDescription: str
    eventDate: date
    eventTime: time
    eventVenue: str
    eventLink: str
    location: str
    communityName: str

    model_config = {"from_attributes": True}


class EventAdminResponse(BaseModel):
    id: int
    eventName: str
    eventDescription: str
    eventDate: date
    eventTime: time
    eventVenue: str
    eventLink: str
    location: str
    communityName: str
    email: str
    approved: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class OTPVerifyRequest(BaseModel):
    otp: str

    @field_validator("otp")
    @classmethod
    def validate_otp(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or len(v) != OTP_LENGTH:
            raise ValueError(f"OTP must be exactly {OTP_LENGTH} digits")
        return v


class AdminLoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Username cannot be empty")
        if len(v) > 100:
            raise ValueError("Username too long")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not v:
            raise ValueError("Password cannot be empty")
        if len(v) > 200:
            raise ValueError("Password too long")
        return v


class AdminApproveRequest(BaseModel):
    id: int

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("Event ID must be a positive integer")
        return v


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables on startup."""
    logger.info("Starting up — creating database tables")
    SQLModel.metadata.create_all(engine)
    logger.info("Database tables ready")

    # with Session(engine) as session:
    #     existing_admin = session.exec(
    #         select(Admin).where(Admin.username == "admin")
    #     ).first()
    #     if not existing_admin:
    #         admin = Admin(
    #             username="admin",
    #             hashed_password=hash_password("ADMIN123"),
    #         )
    #         session.add(admin)
    #         session.commit()
    #         logger.info("Seeded dev admin user (username: admin)")

    yield  # App runs here

    logger.info("Shutting down")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="Tamil Nadu Events API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # or ["*"] during development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ---------------------------------------------------------------------------
# Admin token verification dependency
# ---------------------------------------------------------------------------
def verify_admin_token(
    token: str = Depends(extract_bearer_token),
    session: Session = Depends(get_session),
) -> Admin:
    """Decode JWT, look up admin, and cross-check the stored token."""
    payload = decode_jwt(token)
    username = payload.get("username")
    if not username or not isinstance(username, str):
        raise HTTPException(status_code=401, detail="Invalid token payload")

    admin = session.exec(
        select(Admin).where(Admin.username == username)
    ).first()
    if not admin:
        raise HTTPException(status_code=401, detail="Admin not found")

    # Cross-check: token must exactly match what is stored in DB
    if admin.token != token:
        raise HTTPException(status_code=401, detail="Token mismatch. Please login again.")

    logger.info("Admin authenticated: %s", username)
    return admin


# ---------------------------------------------------------------------------
# Routes — Public
# ---------------------------------------------------------------------------
@app.get("/events", response_model=list[EventPublicResponse])
def get_approved_events(session: Session = Depends(get_session)):
    """Return all approved events with public fields only."""
    statement = select(Event).where(Event.approved == True)
    events = session.exec(statement).all()
    logger.info("GET /events — returned %d approved events", len(events))
    return events


@app.post("/events")
def create_event(
    event_data: EventCreate,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
):
    """
    Submit a new event. Sends OTP to the provided email (async).
    Returns a JWT for use in /verifyotp.
    """
    email = event_data.email
    print(event_data)
    logger.info(
        "POST /events — new submission: name=%s, date=%s, venue=%s, location=%s, community=%s, email=%s",
        event_data.eventName, event_data.eventDate, event_data.eventVenue,
        event_data.location, event_data.communityName, email,
    )

    # --- Rate limit: check if this email posted within the last 30 minutes ---
    now_utc = datetime.now(timezone.utc)
    cooldown_cutoff = now_utc - timedelta(minutes=POST_COOLDOWN_MINUTES)
    recent = session.exec(
        select(RecentPost).where(
            RecentPost.email == email,
            RecentPost.created_at >= cooldown_cutoff,
        )
    ).first()
    if recent:
        created_utc = to_utc(recent.created_at)
        remaining = (created_utc + timedelta(minutes=POST_COOLDOWN_MINUTES)) - now_utc
        remaining_mins = max(1, int(remaining.total_seconds() // 60))
        logger.warning(
            "POST /events — rate limited email=%s, remaining=%d min (created_at=%s, created_utc=%s, now_utc=%s)",
            email, remaining_mins, recent.created_at, created_utc, now_utc,
        )
        raise HTTPException(
            status_code=429,
            detail=f"You have already submitted an event recently. Please wait {remaining_mins} minute(s) before trying again.",
        )

    # --- Duplicate check: reject if eventLink already exists ---
    existing_event = session.exec(
        select(Event).where(Event.eventLink == event_data.eventLink)
    ).first()
    if existing_event:
        logger.warning("POST /events — duplicate link rejected (exists in events): %s", event_data.eventLink)
        raise HTTPException(
            status_code=409,
            detail="An event with this link already exists.",
        )

    existing_temp = session.exec(
        select(TempEvent).where(TempEvent.eventLink == event_data.eventLink)
    ).first()
    if existing_temp:
        logger.warning("POST /events — duplicate link rejected (exists in temp_events): %s", event_data.eventLink)
        raise HTTPException(
            status_code=409,
            detail="An event with this link is already pending verification.",
        )

    # --- Store event in temp table ---
    temp_event = TempEvent(
        eventName=event_data.eventName,
        eventDescription=event_data.eventDescription,
        eventDate=event_data.eventDate,
        eventTime=event_data.eventTime,
        eventVenue=event_data.eventVenue,
        eventLink=event_data.eventLink,
        location=event_data.location,
        communityName=event_data.communityName,
        email=email,
    )
    session.add(temp_event)
    session.commit()
    session.refresh(temp_event)

    logger.info("POST /events — temp event created: id=%d, name=%s", temp_event.id, temp_event.eventName)

    # --- Generate OTP, hash it, store record ---
    otp_plain = "".join([str(random.randint(0, 9)) for _ in range(OTP_LENGTH)])
    otp_hashed = hash_otp(otp_plain)

    otp_record = OTPRecord(
        email=email,
        otp_hash=otp_hashed,
        temp_event_id=temp_event.id,
    )
    session.add(otp_record)
    session.commit()

    logger.info("POST /events — OTP generated for email=%s, temp_event_id=%d", email, temp_event.id)

    # --- Send OTP via email (async — non-blocking) ---
    background_tasks.add_task(_send_otp_email_sync, email, otp_plain)
    logger.info("POST /events — OTP email queued for background send to %s", email)

    # --- Create JWT with email payload ---
    token = create_jwt({"email": email})

    logger.info("POST /events — response sent, OTP email sending in background")
    return {"message": "OTP sent to your email. Please verify to complete submission.", "token": token}


@app.post("/verifyotp")
def verify_otp_endpoint(
    otp_data: OTPVerifyRequest,
    token: str = Depends(extract_bearer_token),
    session: Session = Depends(get_session),
):
    """
    Verify OTP and move the event from temp to main DB.
    Requires JWT in Authorization header.
    """
    # --- Decode JWT and extract email ---
    payload = decode_jwt(token)
    email = payload.get("email")
    if not email or not isinstance(email, str):
        raise HTTPException(status_code=401, detail="Invalid token payload")

    # Normalize email
    email = email.strip().lower()

    logger.info("POST /verifyotp — OTP verification attempt for email=%s", email)

    # --- Find OTP record for this email ---
    otp_record = session.exec(
        select(OTPRecord).where(OTPRecord.email == email)
    ).first()

    if not otp_record:
        logger.warning("POST /verifyotp — no pending OTP found for email=%s", email)
        raise HTTPException(status_code=400, detail="No pending OTP found for this email")

    # --- Check OTP expiry (10 minutes) ---
    now_utc = datetime.now(timezone.utc)
    created_utc = to_utc(otp_record.created_at)
    otp_age = now_utc - created_utc
    if otp_age > timedelta(minutes=OTP_EXPIRY_MINUTES):
        # Clean up expired OTP and temp event
        logger.warning(
            "POST /verifyotp — OTP expired for email=%s (age=%s, created_utc=%s, now_utc=%s)",
            email, otp_age, created_utc, now_utc,
        )
        temp_event = session.get(TempEvent, otp_record.temp_event_id)
        session.delete(otp_record)
        if temp_event:
            session.delete(temp_event)
        session.commit()
        raise HTTPException(status_code=400, detail="OTP has expired. Please submit the event again.")

    # --- Verify OTP hash ---
    if not verify_otp_hash(otp_data.otp, otp_record.otp_hash):
        logger.warning("POST /verifyotp — invalid OTP for email=%s", email)
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # --- Load temp event ---
    temp_event = session.get(TempEvent, otp_record.temp_event_id)
    if not temp_event:
        session.delete(otp_record)
        session.commit()
        logger.error("POST /verifyotp — temp event not found for otp_record=%d", otp_record.id)
        raise HTTPException(status_code=404, detail="Temporary event not found")

    # --- Cross-check: temp event email must match JWT email ---
    if temp_event.email != email:
        logger.error("POST /verifyotp — email mismatch: token=%s, temp_event=%s", email, temp_event.email)
        raise HTTPException(status_code=403, detail="Email mismatch between token and event record")

    # --- Move to main events table (approved=False) ---
    event = Event(
        eventName=temp_event.eventName,
        eventDescription=temp_event.eventDescription,
        eventDate=temp_event.eventDate,
        eventTime=temp_event.eventTime,
        eventVenue=temp_event.eventVenue,
        eventLink=temp_event.eventLink,
        location=temp_event.location,
        communityName=temp_event.communityName,
        email=temp_event.email,
        approved=False,
    )
    session.add(event)

    # --- Record in recent posts for rate limiting ---
    recent_post = RecentPost(email=email)
    session.add(recent_post)

    # --- Cleanup: delete OTP record and temp event ---
    session.delete(otp_record)
    session.delete(temp_event)

    session.commit()

    logger.info(
        "POST /verifyotp — OTP verified, event moved to main table: name=%s, email=%s, approved=False",
        event.eventName, email,
    )

    return {"message": "Email verified successfully. Your event is pending admin approval."}


# ---------------------------------------------------------------------------
# Routes — Admin
# ---------------------------------------------------------------------------
@app.post("/admin/login")
def admin_login(login_data: AdminLoginRequest, session: Session = Depends(get_session)):
    """Authenticate admin and return a new JWT. Token is stored in DB."""
    logger.info("POST /admin/login — login attempt for username=%s", login_data.username)

    admin = session.exec(
        select(Admin).where(Admin.username == login_data.username)
    ).first()

    if not admin:
        logger.warning("POST /admin/login — failed: username=%s not found", login_data.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(login_data.password, admin.hashed_password):
        logger.warning("POST /admin/login — failed: wrong password for username=%s", login_data.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate new token and store in DB
    token = create_jwt({"username": admin.username})
    admin.token = token
    session.add(admin)
    session.commit()

    logger.info("POST /admin/login — success for username=%s", login_data.username)
    return {"token": token}


@app.get("/admin/events", response_model=list[EventAdminResponse])
def get_all_events_admin(admin: Admin = Depends(verify_admin_token), session: Session = Depends(get_session)):
    """Return all events (including unapproved) for admin review."""
    events = session.exec(select(Event)).all()
    logger.info("GET /admin/events — returned %d events (admin=%s)", len(events), admin.username)
    return events


@app.post("/admin/approve")
def approve_event(
    approve_data: AdminApproveRequest,
    admin: Admin = Depends(verify_admin_token),
    session: Session = Depends(get_session),
):
    """Approve an event by ID. Requires admin token."""
    logger.info("POST /admin/approve — admin=%s approving event id=%d", admin.username, approve_data.id)

    event = session.get(Event, approve_data.id)
    if not event:
        logger.warning("POST /admin/approve — event id=%d not found", approve_data.id)
        raise HTTPException(status_code=404, detail="Event not found")

    if event.approved:
        logger.info("POST /admin/approve — event id=%d already approved", approve_data.id)
        return {"message": "Event is already approved"}

    event.approved = True
    session.add(event)
    session.commit()

    logger.info("POST /admin/approve — event approved: id=%d, name=%s", event.id, event.eventName)
    return {"message": f"Event '{event.eventName}' (ID: {event.id}) has been approved."}


@app.delete("/admin/delete")
def delete_event(
    delete_data: AdminApproveRequest,
    admin: Admin = Depends(verify_admin_token),
    session: Session = Depends(get_session),
):
    """Delete an event by ID. Requires admin token."""
    logger.info("DELETE /admin/delete — admin=%s deleting event id=%d", admin.username, delete_data.id)

    event = session.get(Event, delete_data.id)
    if not event:
        logger.warning("DELETE /admin/delete — event id=%d not found", delete_data.id)
        raise HTTPException(status_code=404, detail="Event not found")

    event_name = event.eventName
    event_id = event.id
    session.delete(event)
    session.commit()

    logger.info("DELETE /admin/delete — event deleted: id=%d, name=%s", event_id, event_name)
    return {"message": f"Event '{event_name}' (ID: {event_id}) has been deleted."}
