from sqlmodel import create_engine, Session
from config import DB_HOST, DB_PORT, DB_NAME, DB_USERNAME, DB_PASSWORD

# ---------------------------------------------------------------------------
# Database engine
# ---------------------------------------------------------------------------
engine = create_engine(f"postgresql+psycopg://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}", echo=False)


def get_session():
    with Session(engine) as session:
        yield session
