import datetime
import jwt
from dotenv import load_dotenv
import os

load_dotenv()

PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH")
PUBLIC_KEY_PATH = os.getenv("PUBLIC_KEY_PATH")


def load_key(path: str) -> str:
    with open(path, "r") as file:
        return file.read()


if PRIVATE_KEY_PATH:
    PRIVATE_KEY = load_key(PRIVATE_KEY_PATH)
else:
    raise IOError(f"Could Not load private key from path {PRIVATE_KEY_PATH}")
if PUBLIC_KEY_PATH:
    PUBLIC_KEY = load_key(PUBLIC_KEY_PATH)
else:
    raise IOError(f"Could not load public key from path {PUBLIC_KEY_PATH}")


def create_jwt_token(user_id: int, expires_delta: int = 60) -> str:
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

    token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")

    return token
