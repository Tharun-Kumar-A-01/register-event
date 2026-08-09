import os
import logging
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Load .env
# ---------------------------------------------------------------------------
load_dotenv()

DB_HOST = os.environ.get("DB_HOST")
DB_PORT = os.environ.get("DB_PORT")
DB_NAME = os.environ.get("DB_NAME")
DB_USERNAME = os.environ.get("DB_USERNAME")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
JWT_SECRET = os.environ.get("JWT_SECRET")
MAILJET_API_KEY = os.environ.get("MJ_APIKEY_PUBLIC")
MAILJET_API_SECRET = os.environ.get("MJ_APIKEY_PRIVATE")
MAILJET_SENDER_EMAIL = os.environ.get("MJ_SENDER_EMAIL")

if not all([DB_HOST, DB_PORT, DB_NAME, DB_USERNAME, DB_PASSWORD, JWT_SECRET, MAILJET_API_KEY, MAILJET_API_SECRET, MAILJET_SENDER_EMAIL]):
    raise RuntimeError(
        "Missing required environment variables. "
        "Set DB_HOST, DB_PORT, DB_NAME, DB_USERNAME, DB_PASSWORD, JWT_SECRET, MJ_APIKEY_PUBLIC, MJ_APIKEY_PRIVATE, MJ_SENDER_EMAIL in .env"
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
