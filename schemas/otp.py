from pydantic import BaseModel, field_validator
from config import OTP_LENGTH


class OTPVerifyRequest(BaseModel):
    otp: str

    @field_validator("otp")
    @classmethod
    def validate_otp(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or len(v) != OTP_LENGTH:
            raise ValueError(f"OTP must be exactly {OTP_LENGTH} digits")
        return v
