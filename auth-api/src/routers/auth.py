from fastapi import APIRouter, Depends, Response, HTTPException, status
from loggingconf import setup_logging
from sqlalchemy.orm import Session
from utils.token import create_jwt_token,create_jwt_auth_token , verify_jwt_token
from utils.hashing import verify_password
from utils.db import get_db
from models.user_login import UserLogin
from models.user import User
from models.refresh_token_request import RefreshTokenRequest
from models.auth_token_request import AuthTokenRequest
from jwt.exceptions import InvalidTokenError

router = APIRouter(prefix="/api/v1/auth")
logger = setup_logging()


@router.get("/")
def test_auth():
    return "Welcome to the auth api"


@router.get("log")
def log():
    return {"status": 200, "msg": "you are logged in"}

@router.post("/login")
async def login(user_login: UserLogin, db: Session = Depends(get_db)):
    user_record = db.query(User).filter(User.email == user_login.email).first()
    if user_record:
        is_password_verified = verify_password(
            user_login.password, str(user_record.hashed_password)
        )
        if is_password_verified:
            logger.info(f"user: {user_login.email} has logged in")
            auth_token = create_jwt_auth_token(user_id=1, audience=user_login.audience)
            refresh_token = create_jwt_token(user_id=1, audience=user_login.audience)
            return {"authToken": auth_token, "refreshToken": refresh_token}
        else:
            logger.info(f"User: {user_login.email} has failed login invalid password")
            raise HTTPException(
                status_code=401, detail="Login failed invalid credentials"
            )
    logger.info(f"Login failed user {user_login.email} not found")
    raise HTTPException(status_code=404, detail="Login failed invalid credentials")


@router.post("/verify_refresh_token")
def verify_refresh_token(refreshTokenRequest: RefreshTokenRequest):
    if refreshTokenRequest.refreshToken:
        try:
            verify_jwt_token(
                refreshTokenRequest.refreshToken, refreshTokenRequest.audience
            )
            return {"status": 200, "authToken": "test"}
        except InvalidTokenError as e:
            logger.info(e)
            raise HTTPException(status_code=401, detail="Login failed invalid token 1")
    print(refreshTokenRequest.refreshToken)
    return HTTPException(status_code=401, detail="Login failed invalid token 2")


@router.post("/verify_auth_token")
def verify_auth_token(authTokenRequest: AuthTokenRequest):
    if authTokenRequest.authToken:
        try:
            payload = verify_jwt_token(authTokenRequest.authToken, authTokenRequest.audience)
            return {"status": 200, "payload": payload}
        except InvalidTokenError as e:
            raise HTTPException(status_code=401, detail="Login failed invalid token")
    return HTTPException(status_code=401, detail="Login failed invalid token")
