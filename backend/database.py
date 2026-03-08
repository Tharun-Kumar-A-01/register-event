from sqlmodel import create_engine, Session
from config import DATABASE_URL

# ---------------------------------------------------------------------------
# Database engine
# ---------------------------------------------------------------------------
engine = create_engine(DATABASE_URL, echo=False)


def get_session():
    with Session(engine) as session:
        yield session
