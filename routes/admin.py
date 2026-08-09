from fastapi import APIRouter, HTTPException, Depends
from sqlmodel import Session, select

from config import logger
from database import get_session
from models import Event, Admin
from schemas import EventAdminResponse, AdminLoginRequest, AdminApproveRequest
from utils.security import (
    verify_password,
    create_jwt,
    decode_jwt,
    extract_bearer_token,
)

router = APIRouter(prefix="/admin")


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

    admin = session.exec(select(Admin).where(Admin.username == username)).first()
    if not admin:
        raise HTTPException(status_code=401, detail="Admin not found")

    # Cross-check: token must exactly match what is stored in DB
    if admin.token != token:
        raise HTTPException(
            status_code=401, detail="Token mismatch. Please login again."
        )

    logger.info("Admin authenticated: %s", username)
    return admin


# ---------------------------------------------------------------------------
# POST /admin/login
# ---------------------------------------------------------------------------
@router.post("/login")
def admin_login(login_data: AdminLoginRequest, session: Session = Depends(get_session)):
    """Authenticate admin and return a new JWT. Token is stored in DB."""
    logger.info(
        "POST /admin/login — login attempt for username=%s", login_data.username
    )

    admin = session.exec(
        select(Admin).where(Admin.username == login_data.username)
    ).first()

    if not admin:
        logger.warning(
            "POST /admin/login — failed: username=%s not found", login_data.username
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(login_data.password, admin.hashed_password):
        logger.warning(
            "POST /admin/login — failed: wrong password for username=%s",
            login_data.username,
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate new token and store in DB
    token = create_jwt({"username": admin.username})
    admin.token = token
    session.add(admin)
    session.commit()

    logger.info("POST /admin/login — success for username=%s", login_data.username)
    return {"token": token}


# ---------------------------------------------------------------------------
# GET /admin/events
# ---------------------------------------------------------------------------
@router.get("/events", response_model=list[EventAdminResponse])
def get_all_events_admin(
    admin: Admin = Depends(verify_admin_token),
    session: Session = Depends(get_session),
):
    """Return all events (including unapproved) for admin review."""
    events = session.exec(select(Event)).all()
    logger.info(
        "GET /admin/events — returned %d events (admin=%s)",
        len(events),
        admin.username,
    )
    return events


# ---------------------------------------------------------------------------
# POST /admin/approve
# ---------------------------------------------------------------------------
@router.post("/approve")
def approve_event(
    approve_data: AdminApproveRequest,
    admin: Admin = Depends(verify_admin_token),
    session: Session = Depends(get_session),
):
    """Approve an event by ID. Requires admin token."""
    logger.info(
        "POST /admin/approve — admin=%s approving event id=%d",
        admin.username,
        approve_data.id,
    )

    event = session.get(Event, approve_data.id)
    if not event:
        logger.warning(
            "POST /admin/approve — event id=%d not found", approve_data.id
        )
        raise HTTPException(status_code=404, detail="Event not found")

    if event.approved:
        logger.info(
            "POST /admin/approve — event id=%d already approved", approve_data.id
        )
        return {"message": "Event is already approved"}

    event.approved = True
    session.add(event)
    session.commit()

    logger.info(
        "POST /admin/approve — event approved: id=%d, name=%s",
        event.id,
        event.eventName,
    )
    return {"message": f"Event '{event.eventName}' (ID: {event.id}) has been approved."}


# ---------------------------------------------------------------------------
# DELETE /admin/delete
# ---------------------------------------------------------------------------
@router.delete("/delete")
def delete_event(
    delete_data: AdminApproveRequest,
    admin: Admin = Depends(verify_admin_token),
    session: Session = Depends(get_session),
):
    """Delete an event by ID. Requires admin token."""
    logger.info(
        "DELETE /admin/delete — admin=%s deleting event id=%d",
        admin.username,
        delete_data.id,
    )

    event = session.get(Event, delete_data.id)
    if not event:
        logger.warning(
            "DELETE /admin/delete — event id=%d not found", delete_data.id
        )
        raise HTTPException(status_code=404, detail="Event not found")

    event_name = event.eventName
    event_id = event.id
    session.delete(event)
    session.commit()

    logger.info(
        "DELETE /admin/delete — event deleted: id=%d, name=%s", event_id, event_name
    )
    return {"message": f"Event '{event_name}' (ID: {event_id}) has been deleted."}
