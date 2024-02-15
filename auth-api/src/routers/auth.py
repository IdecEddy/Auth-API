from fastapi import APIRouter
from loggingconf import setup_logging
from sqlalchemy import create_engine, DateTime, Column, Integer, String
from sqlalchemy.orm import Session, declarative_base
from sqlalchemy.sql import func
from pathlib import Path
from pydantic import BaseModel, EmailStr
import bcrypt
import jwt
import datetime
from dotenv import load_dotenv
import os

router = APIRouter(
    prefix="/api/v1/auth",
)
logger = setup_logging()
Base = declarative_base()

load_dotenv()

PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH")
PUBLIC_KEY_PATH = os.getenv("PUBLIC_KEY_PATH")

def load_key(path: str) -> str:
    with open(path, 'r') as file:
        return file.read()

PRIVATE_KEY = load_key(PRIVATE_KEY_PATH)
PUBLIC_KEY = load_key(PUBLIC_KEY_PATH)

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



def hash_password(password: str) -> str:
    """
    Hashes a password with a salt.

    Args:
    password (str): The plaintext password to hash.

    Returns:
    str: The hashed and salted password.
    """
    password_bytes = password.encode("utf-8")

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)

    return hashed_password.decode("utf-8")


def verify_password(submitted_password: str, stored_hash: str) -> bool:
    """
    Verifies a submitted password against a stored hash.

    Args:
    submitted_password (str): The plaintext password submitted by the user.
    stored_hash (str): The stored hash against which to verify the password.

    Returns:
    bool: True if the password matches the hash, False otherwise.
    """
    submitted_password_bytes = submitted_password.encode("utf-8")
    stored_hash_bytes = stored_hash.encode("utf-8")
    return bcrypt.checkpw(submitted_password_bytes, stored_hash_bytes)


def create_jwt_token(user_id: int, secret_key: str, expires_delta: int = 60) -> str:
    """
    Create a JWT token.

    Args:
    user_id (int): User identifier to include in the token.
    secret_key (str): The secret key used to sign the token.
    expires_delta (int): Token expiration time in minutes.

    Returns:
    str: Encoded JWT token.
    """
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=expires_delta)
    iss = "auth-api"
    sub = "device-id"
    aud = "requesting-api"
    payload = {
        "user_id": user_id,
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "exp": expire,
    }

    token = jwt.encode(payload, secret_key, algorithm="RS256")

    return token


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
                token = create_jwt_token(user_id=1, secret_key=PRIVATE_KEY)
                return token
        logger.warning("The user failed to login")
        return "login failed"
