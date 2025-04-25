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
import datetime

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
                user_id=user_record.id,
                audience=user_login.audience,
                expires_delta=datetime.timedelta(days=30)
            )
            refresh_token_db = RefreshTokenDB(token=refresh_token, version=1)
            db.add(refresh_token_db)
            db.commit()
            logger.info(f"saving Token with version: 1")
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
        authToken = tokensAuthRequest.authToken
        tokenAudience = tokensAuthRequest.audience
        if authorize_with_auth_token(authToken, tokenAudience):
            return {
                "method": "auth_token",
                "status": 200,
            }
    if tokensAuthRequest.refreshToken:
        refreshToken = tokensAuthRequest.refreshToken
        tokenAudience = tokensAuthRequest.audience
        payload = authorize_with_refresh_token(refreshToken, tokenAudience, db)
        return {
            "method": "refresh_token",
            "status": 200,
            "refreshToken": payload["newRefreshToken"],
            "authToken": payload["newAuthToken"],
        }
    logger.info("both auth and refresh authorization failed.")
    raise HTTPException(status_code=401, detail="Login failed invalid token")


def authorize_with_auth_token(auth_token: str, tokenAudience: str):
    # Verify the token is a valid token
    try:
        verify_jwt_token(token=auth_token, audience=tokenAudience)
        logger.info("Auth token is valid")
        return True
    except InvalidTokenError:
        logger.info("Invalid auth token falling back to refresh token")
        return False


def authorize_with_refresh_token(refresh_token: str, tokenAudience: str, db: Session):
    # search database for token return 401 if we can't find it.
    logger.info("Searching Database for refresh token provided")
    token_record = (
        db.query(RefreshTokenDB).filter(RefreshTokenDB.token == refresh_token).first()
    )
    if not token_record:
        logger.info("Refresh token not found in database")
        raise HTTPException(status_code=401, detail="Refresh token not found!")
    logger.info(
        f"refresh token found in database. token version = {token_record.version}"
    )
    # verify the token using JWT verify to make sure it's a valid token.
    try:
        payload = verify_jwt_token(token=refresh_token, audience=tokenAudience)
        logger.info("Refresh token is valid")
    except InvalidTokenError:
        logger.info("Invalid refresh token")
        # Delete the invalid refresh token from the database
        db.delete(token_record)
        db.commit()
        logger.info("Deleted invalid refresh token from database")
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    # ensure that the version in the verified token and the token in the database match.
    token_version = payload.get("version")
    if token_version != token_record.version:
        logger.info(
            f"Token version mismatch: token version = {token_version}, "
            f"database version = {token_record.version}"
        )
        raise HTTPException(status_code=401, detail="Token version mismatch")
    logger.info("token versions match between database and request")
    # Create a new refresh_token using the old one but increment the version by one.
    # Extract the expiration time from the old token
    old_expiration_time = payload.get("exp")
    if not old_expiration_time:
        logger.info("Old token does not have an expiration time")
        raise HTTPException(
            status_code=400, detail="Invalid token: missing expiration time"
        )
    # Calculate the remaining time until the old token's expiration
    remaining_time = old_expiration_time - int(
        datetime.datetime.now(datetime.timezone.utc).timestamp()
    )
    if remaining_time <= 0:
        logger.info("Old token has already expired")
        raise HTTPException(status_code=401, detail="Old token has expired")
    # Use the remaining time to set the expiration for the new token
    expires_delta = datetime.timedelta(seconds=remaining_time)
    new_refresh_token = create_jwt_token(
        user_id=payload.get("user_id"),
        audience=tokenAudience,
        token_version=token_version + 1,
        expires_delta=expires_delta,
    )
    logger.info(f"Generated new refresh token with version: {token_version + 1}")
    # Save the new refresh token to the database
    token_record.token = new_refresh_token
    token_record.version = token_version + 1
    db.commit()
    logger.info("Updated existing refresh token in database")
    # Retrieve the user record based on the user_id from the payload
    user_record = db.query(User).filter(User.id == payload.get("user_id")).first()
    if not user_record:
        logger.info("User not found for the given user_id in the token payload")
        raise HTTPException(status_code=404, detail="User not found")
    logger.info(f"User record found: {user_record.email}")
    # Create a new auth token for the user
    auth_token = create_jwt_auth_token(
        user_id=user_record.id, audience=tokenAudience, role=user_record.role
    )
    logger.info(f"Generated new auth token for user: {user_record.email}")
    return {"newRefreshToken": new_refresh_token, "newAuthToken": auth_token}
    pass
