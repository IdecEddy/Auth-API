from sqlalchemy import DateTime, Column, Integer, String
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func
from models.base import Base

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
