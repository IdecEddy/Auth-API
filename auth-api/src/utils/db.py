from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from pathlib import Path
from models.user import User
from models.base import Base

db_path = Path("auth.db").absolute()
engine = create_engine(rf"sqlite:///{db_path}")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
