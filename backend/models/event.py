from typing import Optional
from datetime import datetime, date, time, timezone
from sqlmodel import SQLModel, Field
from sqlalchemy import Column, DateTime


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
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )


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
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )
