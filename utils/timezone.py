from datetime import datetime, timezone


def to_utc(dt: datetime) -> datetime:
    """
    Convert a datetime to UTC.
    - If naive (no tzinfo): assume it is in the server's local timezone and
      convert to UTC. This fixes the mismatch when the DB returns naive
      timestamps in local time (e.g. IST).
    - If aware: convert to UTC directly.
    """
    if dt.tzinfo is None:
        local_dt = dt.astimezone()  # attach local tz
        return local_dt.astimezone(timezone.utc)
    return dt.astimezone(timezone.utc)
