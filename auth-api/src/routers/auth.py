from fastapi import APIRouter, Depends, HTTPException
from jwt.exceptions import InvalidTokenError
from sqlalchemy.orm import Session

from loggingconf import setup_logging
from models.auth_token_request import AuthTokenRequest
from models.refresh_token_request import RefreshTokenRequest
from models.token_auth_request import TokenAuthRequest
from models.user import User
from models.user_login import UserLogin
from models.refresh_token_db import RefreshTokenDB
from utils.db import get_db
from utils.hashing import verify_password
from utils.token import create_jwt_auth_token, create_jwt_token, verify_jwt_token

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
            refresh_token = create_jwt_token(
                user_id=user_record.id, audience=user_login.audience
            )
            refresh_token_db = RefreshTokenDB(token=refresh_token, version=1)
            db.add(refresh_token_db)
            db.commit()
            logger.info(f"saving Token: {refresh_token} with version: 1")
            return {"refreshToken": refresh_token}
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
        except InvalidTokenError:
            raise HTTPException(status_code=401, detail="Login failed invalid token")
    return HTTPException(status_code=401, detail="Login failed invalid token 2")


@router.post("/verify_auth_token")
def verify_auth_token(authTokenRequest: AuthTokenRequest):
    if authTokenRequest.authToken:
        try:
            print(authTokenRequest.authToken)
            payload = verify_jwt_token(
                authTokenRequest.authToken, authTokenRequest.audience
            )
            return {"status": 200, "payload": payload}
        except InvalidTokenError:
            raise HTTPException(status_code=401, detail="Login failed invalid token")
    return HTTPException(status_code=401, detail="Login failed invalid token")


@router.post("/verifyWithTokens")
async def verify_tokens(
    tokensAuthRequest: TokenAuthRequest, db: Session = Depends(get_db)
):
    if tokensAuthRequest.authToken:
        # Try to login using the auth token
        logger.info("Trying to login with auth token")
        try:
            # Verify the token
            verify_jwt_token(tokensAuthRequest.authToken, tokensAuthRequest.audience)
            logger.info("Token verified successfully")
            return {
                "status": 200,
                "authToken": tokensAuthRequest.authToken,
                "refreshToken": tokensAuthRequest.refreshToken,
            }
        except InvalidTokenError:
            logger.info(
                "Failed to login using auth token falling back to refresh token"
            )
    if tokensAuthRequest.refreshToken:
        logger.info("Trying to login with refresh token")
        try:
            refreshToken = verify_jwt_token(
                tokensAuthRequest.refreshToken, tokensAuthRequest.audience
            )
        except InvalidTokenError:
            raise HTTPException(status_code=401, detail="Login failed invalid token")
        logger.info("Token verified successfully")
        logger.info(f'searching for {tokensAuthRequest}')
        refresh_token_record = (
            db.query(RefreshTokenDB)
            .filter(RefreshTokenDB.token == tokensAuthRequest.refreshToken)
            .first()
        )
        if not refresh_token_record:
            logger.info(f'could not find {tokensAuthRequest.refreshToken}')
            raise HTTPException(status_code=404, detail="Refresh token not found")
        logger.info(
            f"We got a record with the provided token version {refresh_token_record.version}"
        )
        refresh_token_id = refresh_token_record.id
        new_version = refreshToken["version"] + 1
        new_refresh_token = create_jwt_token(
            user_id=refreshToken["user_id"],
            audience=tokensAuthRequest.audience,
            token_version=new_version,
        )
        db.query(RefreshTokenDB).filter(RefreshTokenDB.id == refresh_token_id).update(
            {"token": new_refresh_token, "version": new_version}
        )
        db.commit()
        user_record = db.query(User).filter(User.id == refreshToken["user_id"]).first()
        auth_token = create_jwt_auth_token(
            user_id=refreshToken["user_id"],
            audience=tokensAuthRequest.audience,
            role=user_record.role,
            expires_delta=5,
        )
        logger.info("New authentication token issued.")
        logger.info(f'sent off new refresh token {new_refresh_token}')
        return {
            "status": 200,
            "authToken": auth_token,
            "refreshToken": new_refresh_token,
        }
