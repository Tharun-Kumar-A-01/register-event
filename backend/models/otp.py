from typing import Optional
from datetime import datetime, timezone
from sqlmodel import SQLModel, Field
from sqlalchemy import Column, DateTime


class OTPRecord(SQLModel, table=True):
    __tablename__ = "otp_records"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str
    otp_hash: str
    temp_event_id: int = Field(foreign_key="temp_events.id")
    resend_count: int = Field(default=0)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )


class RecentPost(SQLModel, table=True):
    __tablename__ = "recent_posts"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )
