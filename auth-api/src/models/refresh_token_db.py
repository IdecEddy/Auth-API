from sqlalchemy import DateTime, Column, Integer, String
from sqlalchemy.sql import func
from models.base import Base


class RefreshTokenDB(Base):
    __tablename__ = "authAPI_Refresh_Token"

    id = Column(Integer, primary_key=True)
    token = Column(String)
    version = Column(Integer, unique=True)
    date_created = Column(DateTime(timezone=True), server_default=func.now())
    date_updated = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):

        return (
            f"<User(token={self.token}, version={self.version},"
            f" date_created={self.date_created},"
            f" date_updated={self.date_updated})>"
        )
