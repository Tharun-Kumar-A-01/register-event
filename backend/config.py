import os
import logging
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Load .env
# ---------------------------------------------------------------------------
load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")
JWT_SECRET = os.environ.get("JWT_SECRET")
GMAIL_USER = os.environ.get("GMAIL_USER")
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD")

if not all([DATABASE_URL, JWT_SECRET, GMAIL_USER, GMAIL_APP_PASSWORD]):
    raise RuntimeError(
        "Missing required environment variables. "
        "Set DATABASE_URL, JWT_SECRET, GMAIL_USER, GMAIL_APP_PASSWORD in .env"
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = 30
OTP_EXPIRY_MINUTES = 10
POST_COOLDOWN_MINUTES = 30
OTP_LENGTH = 6
MAX_STRING_LENGTH = 500
MAX_DESCRIPTION_LENGTH = 2000
MAX_URL_LENGTH = 2048
MAX_EVENT_DATE_YEARS = 2
OTP_RESEND_COOLDOWN_SECONDS = 60
MAX_OTP_RESENDS = 5

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("tamilnadu_events")
