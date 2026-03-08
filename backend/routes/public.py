import random
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from sqlmodel import Session, select

from config import (
    logger,
    POST_COOLDOWN_MINUTES,
    OTP_EXPIRY_MINUTES,
    OTP_LENGTH,
    OTP_RESEND_COOLDOWN_SECONDS,
    MAX_OTP_RESENDS,
)
from database import get_session
from models import Event, TempEvent, OTPRecord, RecentPost
from schemas import EventCreate, EventPublicResponse, OTPVerifyRequest
from utils.security import (
    encode_otp,
    decode_otp,
    create_jwt,
    decode_jwt,
    extract_bearer_token,
)
from utils.email import send_otp_email
from utils.timezone import to_utc

router = APIRouter()


# ---------------------------------------------------------------------------
# Helper: cleanup expired OTP + its temp event for an email
# ---------------------------------------------------------------------------
def _cleanup_expired_otps(email: str, session: Session) -> None:
    """Find and delete all expired OTP records (and their temp events) for an email."""
    otp_records = session.exec(
        select(OTPRecord).where(OTPRecord.email == email)
    ).all()
    now_utc = datetime.now(timezone.utc)
    for otp_record in otp_records:
        created_utc = to_utc(otp_record.created_at)
        otp_age = now_utc - created_utc
        if otp_age > timedelta(minutes=OTP_EXPIRY_MINUTES):
            temp_event = session.get(TempEvent, otp_record.temp_event_id)
            session.delete(otp_record)
            session.flush()  # FK constraint: delete child before parent
            if temp_event:
                session.delete(temp_event)
            logger.info(
                "Cleaned up expired OTP for email=%s, temp_event_id=%d",
                email,
                otp_record.temp_event_id,
            )
    session.commit()


# ---------------------------------------------------------------------------
# Helper: cleanup OTP record + temp event (for max resends, etc.)
# ---------------------------------------------------------------------------
def _cleanup_otp_and_temp_event(otp_record: OTPRecord, session: Session) -> None:
    """Delete an OTP record and its associated temp event."""
    temp_event = session.get(TempEvent, otp_record.temp_event_id)
    session.delete(otp_record)
    session.flush()  # FK constraint: delete child before parent
    if temp_event:
        session.delete(temp_event)
    session.commit()


# ---------------------------------------------------------------------------
# GET /events — list approved events
# ---------------------------------------------------------------------------
@router.get("/events", response_model=list[EventPublicResponse])
def get_approved_events(session: Session = Depends(get_session)):
    """Return all approved events with public fields only."""
    statement = select(Event).where(Event.approved == True)
    events = session.exec(statement).all()
    logger.info("GET /events — returned %d approved events", len(events))
    return events


# ---------------------------------------------------------------------------
# POST /events — create event + send OTP
# ---------------------------------------------------------------------------
@router.post("/events")
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
    logger.info(
        "POST /events — new submission: name=%s, date=%s, venue=%s, location=%s, community=%s, email=%s",
        event_data.eventName,
        event_data.eventDate,
        event_data.eventVenue,
        event_data.location,
        event_data.communityName,
        email,
    )

    # --- Cleanup any expired OTPs for this email first ---
    _cleanup_expired_otps(email, session)

    # --- Check for pending (non-expired) OTP for this email ---
    existing_otp = session.exec(
        select(OTPRecord).where(OTPRecord.email == email)
    ).first()
    if existing_otp:
        logger.warning(
            "POST /events — email=%s already has a pending OTP (temp_event_id=%d)",
            email,
            existing_otp.temp_event_id,
        )
        raise HTTPException(
            status_code=409,
            detail="You already have a pending event submission. Please verify the OTP or wait for it to expire.",
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
            "POST /events — rate limited email=%s, remaining=%d min",
            email,
            remaining_mins,
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
        logger.warning(
            "POST /events — duplicate link rejected (exists in events): %s",
            event_data.eventLink,
        )
        raise HTTPException(
            status_code=409,
            detail="An event with this link already exists.",
        )

    existing_temp = session.exec(
        select(TempEvent).where(TempEvent.eventLink == event_data.eventLink)
    ).first()
    if existing_temp:
        logger.warning(
            "POST /events — duplicate link rejected (exists in temp_events): %s",
            event_data.eventLink,
        )
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

    logger.info(
        "POST /events — temp event created: id=%d, name=%s",
        temp_event.id,
        temp_event.eventName,
    )

    # --- Generate OTP, encode it with JWT, store record ---
    otp_plain = "".join([str(random.randint(0, 9)) for _ in range(OTP_LENGTH)])
    otp_encoded = encode_otp(otp_plain)

    otp_record = OTPRecord(
        email=email,
        otp_hash=otp_encoded,
        temp_event_id=temp_event.id,
        resend_count=0,
    )
    session.add(otp_record)
    session.commit()

    logger.info(
        "POST /events — OTP generated for email=%s, temp_event_id=%d",
        email,
        temp_event.id,
    )

    # --- Send OTP via email (async — non-blocking) ---
    background_tasks.add_task(send_otp_email, email, otp_plain)
    logger.info("POST /events — OTP email queued for background send to %s", email)

    # --- Create JWT with email payload ---
    token = create_jwt({"email": email})

    logger.info("POST /events — response sent, OTP email sending in background")
    return {
        "message": "OTP sent to your email. Please verify to complete submission.",
        "token": token,
    }


# ---------------------------------------------------------------------------
# POST /verifyotp — verify OTP and move event to main table
# ---------------------------------------------------------------------------
@router.post("/verifyotp")
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

    email = email.strip().lower()

    logger.info("POST /verifyotp — OTP verification attempt for email=%s", email)

    # --- Find OTP record for this email ---
    otp_record = session.exec(
        select(OTPRecord).where(OTPRecord.email == email)
    ).first()

    if not otp_record:
        logger.warning("POST /verifyotp — no pending OTP found for email=%s", email)
        raise HTTPException(
            status_code=400, detail="No pending OTP found for this email"
        )

    # --- Check OTP expiry — if expired, cleanup and reject ---
    now_utc = datetime.now(timezone.utc)
    created_utc = to_utc(otp_record.created_at)
    otp_age = now_utc - created_utc
    if otp_age > timedelta(minutes=OTP_EXPIRY_MINUTES):
        logger.warning(
            "POST /verifyotp — OTP expired for email=%s (age=%s)",
            email,
            otp_age,
        )
        _cleanup_otp_and_temp_event(otp_record, session)
        raise HTTPException(
            status_code=400,
            detail="OTP has expired. Please submit the event again.",
        )

    # --- Verify OTP by decoding the JWT-encoded value ---
    stored_otp = decode_otp(otp_record.otp_hash)
    if stored_otp != otp_data.otp:
        logger.warning("POST /verifyotp — invalid OTP for email=%s", email)
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # --- Load temp event ---
    temp_event = session.get(TempEvent, otp_record.temp_event_id)
    if not temp_event:
        session.delete(otp_record)
        session.commit()
        logger.error(
            "POST /verifyotp — temp event not found for otp_record=%d", otp_record.id
        )
        raise HTTPException(status_code=404, detail="Temporary event not found")

    # --- Cross-check: temp event email must match JWT email ---
    if temp_event.email != email:
        logger.error(
            "POST /verifyotp — email mismatch: token=%s, temp_event=%s",
            email,
            temp_event.email,
        )
        raise HTTPException(
            status_code=403, detail="Email mismatch between token and event record"
        )

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

    # --- Cleanup: delete OTP record first (FK constraint), then temp event ---
    session.delete(otp_record)
    session.flush()
    session.delete(temp_event)

    session.commit()

    logger.info(
        "POST /verifyotp — OTP verified, event moved to main table: name=%s, email=%s",
        event.eventName,
        email,
    )

    return {"message": "Email verified successfully. Your event is pending admin approval."}


# ---------------------------------------------------------------------------
# POST /resendotp — resend OTP with cooldown and max resend limit
# ---------------------------------------------------------------------------
@router.post("/resendotp")
def resend_otp(
    background_tasks: BackgroundTasks,
    token: str = Depends(extract_bearer_token),
    session: Session = Depends(get_session),
):
    """
    Resend OTP for a pending event submission.
    - 1-minute cooldown between resends
    - Maximum 5 resends per submission
    - After 5 resends: cleanup temp event + OTP record (too many requests)
    Requires the same JWT issued during POST /events.
    """
    # --- Decode JWT and extract email ---
    payload = decode_jwt(token)
    email = payload.get("email")
    if not email or not isinstance(email, str):
        raise HTTPException(status_code=401, detail="Invalid token payload")

    email = email.strip().lower()

    logger.info("POST /resendotp — resend request for email=%s", email)

    # --- Find existing OTP record ---
    otp_record = session.exec(
        select(OTPRecord).where(OTPRecord.email == email)
    ).first()

    if not otp_record:
        logger.warning("POST /resendotp — no pending OTP found for email=%s", email)
        raise HTTPException(
            status_code=400,
            detail="No pending OTP found for this email. Please submit the event again.",
        )

    # --- Check if OTP has expired — if so, cleanup and reject ---
    now_utc = datetime.now(timezone.utc)
    created_utc = to_utc(otp_record.created_at)
    otp_age = now_utc - created_utc
    if otp_age > timedelta(minutes=OTP_EXPIRY_MINUTES):
        logger.warning(
            "POST /resendotp — OTP expired for email=%s (age=%s)", email, otp_age
        )
        _cleanup_otp_and_temp_event(otp_record, session)
        raise HTTPException(
            status_code=400,
            detail="OTP has expired. Please submit the event again.",
        )

    # --- Check max resend limit — if exceeded, cleanup and reject ---
    if otp_record.resend_count >= MAX_OTP_RESENDS:
        logger.warning(
            "POST /resendotp — max resends reached for email=%s (count=%d)",
            email,
            otp_record.resend_count,
        )
        _cleanup_otp_and_temp_event(otp_record, session)
        raise HTTPException(
            status_code=429,
            detail="Too many OTP resend requests. Your submission has been cancelled. Please try again later.",
        )

    # --- Check 1-minute cooldown since last OTP ---
    seconds_since_last = (now_utc - created_utc).total_seconds()
    if seconds_since_last < OTP_RESEND_COOLDOWN_SECONDS:
        remaining = int(OTP_RESEND_COOLDOWN_SECONDS - seconds_since_last)
        logger.warning(
            "POST /resendotp — cooldown active for email=%s, %d seconds remaining",
            email,
            remaining,
        )
        raise HTTPException(
            status_code=429,
            detail=f"Please wait {remaining} second(s) before requesting a new OTP.",
        )

    # --- Verify the temp event still exists ---
    temp_event = session.get(TempEvent, otp_record.temp_event_id)
    if not temp_event:
        session.delete(otp_record)
        session.commit()
        logger.error(
            "POST /resendotp — temp event not found for otp_record=%d", otp_record.id
        )
        raise HTTPException(
            status_code=404,
            detail="Temporary event not found. Please submit the event again.",
        )

    # --- Generate new OTP, encode with JWT, update record ---
    otp_plain = "".join([str(random.randint(0, 9)) for _ in range(OTP_LENGTH)])
    otp_encoded = encode_otp(otp_plain)

    otp_record.otp_hash = otp_encoded
    otp_record.created_at = datetime.now(timezone.utc)
    otp_record.resend_count = otp_record.resend_count + 1
    session.add(otp_record)
    session.commit()

    logger.info(
        "POST /resendotp — new OTP generated for email=%s, resend_count=%d/%d",
        email,
        otp_record.resend_count,
        MAX_OTP_RESENDS,
    )

    # --- Send OTP via email (async — non-blocking) ---
    background_tasks.add_task(send_otp_email, email, otp_plain)
    logger.info("POST /resendotp — OTP email queued for background send to %s", email)

    return {
        "message": "A new OTP has been sent to your email.",
        "resends_remaining": MAX_OTP_RESENDS - otp_record.resend_count,
    }
