from sqlalchemy import create_engine, DateTime, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.sql import func
from pathlib import Path


Base = declarative_base()
db_path = Path("auth.db").absolute()
engine = create_engine(rf"sqlite:///{db_path}")
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    email = Column(String, unique=True)
    hashed_password = Column(String)
    date_created = Column(DateTime(timezone=True), server_default=func.now())
    date_updated = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return (
            f"<User(name={self.name}, email={self.email},"
            f" date_created={self.date_created},"
            f" date_updated={self.date_updated})>"
        )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
