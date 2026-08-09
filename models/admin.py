from typing import Optional
from sqlmodel import SQLModel, Field


class Admin(SQLModel, table=True):
    __tablename__ = "admins"

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    hashed_password: str
    token: Optional[str] = Field(default=None)
