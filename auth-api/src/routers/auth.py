from fastapi import APIRouter, Depends, Response, HTTPException
from loggingconf import setup_logging
from sqlalchemy.orm import Session
from utils.token import create_jwt_token, verify_jwt_token
from utils.hashing import verify_password
from utils.db import get_db
from models.user_login import UserLogin
from models.user import User
from models.auth_token import AuthToken
from jwt.exceptions import InvalidTokenError

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
            logger.info(f"user: {user_login.email} has logged in")
            token = create_jwt_token(user_id=1, audience=user_login.audience)
            return {"authToken": token}
        else:
            logger.info(f"User: {user_login.email} has failed login invalid password")
            raise HTTPException(
                status_code=401, detail="Login failed invalid credentials"
            )
    logger.info(f"Login failed user {user_login.email} not found")
    raise HTTPException(status_code=404, detail="Login failed invalid credentials")


@router.post("/verify_token")
def verify_auth_token(auth_token: AuthToken):
    if auth_token.token:
        try:
            payload = verify_jwt_token(auth_token.token, auth_token.audience)
            return payload
        except InvalidTokenError:
            raise HTTPException(status_code=401, detail="Login failed invalid token")
