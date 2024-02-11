from fastapi import APIRouter
from loggingconf import setup_logging
from sqlalchemy import create_engine, DateTime, Column, Integer, String
from sqlalchemy.orm import Session, declarative_base
from sqlalchemy.sql import func
from pathlib import Path
from pydantic import BaseModel, EmailStr
import bcrypt 

router = APIRouter(
    prefix="/api/v1/auth",
)
logger = setup_logging()

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    email = Column(String, unique=True)
    hashed_password = Column(String) 
    date_created = Column(DateTime(timezone=True), server_default=func.now())
    date_updated = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<User(name={self.name}, email={self.email}, date_created={self.date_created}, date_updated={self.date_updated})>"

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
    password_bytes = password.encode('utf-8')
    
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    
    return hashed_password.decode('utf-8')

def verify_password(submitted_password: str, stored_hash: str) -> bool:
    """
    Verifies a submitted password against a stored hash.

    Args:
    submitted_password (str): The plaintext password submitted by the user.
    stored_hash (str): The stored hash against which to verify the password.

    Returns:
    bool: True if the password matches the hash, False otherwise.
    """
    submitted_password_bytes = submitted_password.encode('utf-8')
    stored_hash_bytes = stored_hash.encode('utf-8')
    return bcrypt.checkpw(submitted_password_bytes, stored_hash_bytes)

@router.get("/")
def test_auth():
    return "Welcome to the auth api"

@router.post("/login")
async def login(user_login: UserLogin):
    db_path = Path("auth.db").absolute()
    engine = create_engine(rf"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    logger.warning(f"Request tried to loggin to {user_login.email} with password {user_login.password}")
    with Session(engine) as session:
        user_record = session.query(User).filter(User.email == user_login.email).first()
        if user_record:
            if verify_password(user_login.password, str(user_record.hashed_password)):
                logger.warning("The user has logged in")
                return("logged in")
        logger.warning("The user failed to login")
        return("login failed")
