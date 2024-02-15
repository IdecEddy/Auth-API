from fastapi import APIRouter, Depends, Response
from loggingconf import setup_logging
from sqlalchemy.orm import Session
from utils.token import create_jwt_token
from utils.hashing import verify_password
from utils.db import get_db, User
from models.user_login import UserLogin

router = APIRouter(prefix="/api/v1/auth")
logger = setup_logging()


@router.get("/")
def test_auth():
    return "Welcome to the auth api"


@router.post("/login")
async def login(
    user_login: UserLogin, response: Response, db: Session = Depends(get_db)
):
    user_record = db.query(User).filter(User.email == user_login.email).first()
    if user_record:
        is_password_verified = verify_password(
            user_login.password, str(user_record.hashed_password)
        )
        if is_password_verified:
            logger.warning("The user has logged in")
            token = create_jwt_token(user_id=1)
            response.set_cookie(
                key="auth_token",
                value=token,
                httponly=True,
                max_age=1800,
                expires=1800,
                secure=True,
                samesite="lax",
            )
            return Response(content="User logged it", status_code=200)
    logger.warning("The user failed to login")
    return Response(content="User login failed", status_code=401)
