import re
from config import MAX_STRING_LENGTH, MAX_URL_LENGTH


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
