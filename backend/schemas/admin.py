from pydantic import BaseModel, field_validator


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
