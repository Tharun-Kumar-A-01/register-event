from datetime import date, time, datetime
from pydantic import BaseModel, EmailStr, field_validator, field_serializer
from config import MAX_DESCRIPTION_LENGTH, MAX_EVENT_DATE_YEARS
from utils.validators import sanitize_string, validate_url


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
        today = date.today()
        if v < today:
            raise ValueError("Event date cannot be in the past")
        max_date = date(today.year + MAX_EVENT_DATE_YEARS, today.month, today.day)
        if v > max_date:
            raise ValueError(
                f"Event date cannot be more than {MAX_EVENT_DATE_YEARS} years in the future"
            )
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

    @field_serializer("eventTime")
    def serialize_time(self, value: time, _info) -> str:
        return value.strftime("%H:%M")


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

    @field_serializer("eventTime")
    def serialize_time(self, value: time, _info) -> str:
        return value.strftime("%H:%M")
