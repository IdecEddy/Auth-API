from fastapi import APIRouter, Depends
from loggingconf import setup_logging
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from utils.token import create_jwt_token
from utils.hashing import verify_password
from utils.db import get_db, User

router = APIRouter(prefix="/api/v1/auth")
logger = setup_logging()


class UserLogin(BaseModel):
    email: EmailStr
    password: str


@router.get("/")
def test_auth():
    return "Welcome to the auth api"


@router.post("/login")
async def login(user_login: UserLogin, db: Session = Depends(get_db)):
    user_record = db.query(User).filter(User.email == user_login.email).first()
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
