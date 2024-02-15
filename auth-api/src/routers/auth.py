from fastapi import APIRouter
from loggingconf import setup_logging
from sqlalchemy import create_engine, DateTime, Column, Integer, String
from sqlalchemy.orm import Session, declarative_base
from sqlalchemy.sql import func
from pathlib import Path
from pydantic import BaseModel, EmailStr
from utils.token import create_jwt_token
from utils.hashing import verify_password

router = APIRouter(
    prefix="/api/v1/auth",
)
logger = setup_logging()
Base = declarative_base()


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


class UserLogin(BaseModel):
    email: EmailStr
    password: str


@router.get("/")
def test_auth():
    return "Welcome to the auth api"


@router.post("/login")
async def login(user_login: UserLogin):
    db_path = Path("auth.db").absolute()
    engine = create_engine(rf"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    logger.warning((
        f"Request tried to loggin to {user_login.email}"
        f" with password {user_login.password}"
    ))
    with Session(engine) as session:
        user_record = session.query(User).filter(User.email == user_login.email).first()
        if user_record:
            is_password_verified = verify_password(
                user_login.password, str(user_record.hashed_password)
            )
            if is_password_verified:
                logger.warning("The user has logged in")
                token = create_jwt_token(user_id=1)
                return token
        logger.warning("The user failed to login")
        return "login failed"
