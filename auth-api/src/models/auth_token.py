from pydantic import BaseModel
from typing import Optional


class AuthToken(BaseModel):
    refreshToken: str
    authToken: Optional[str] = None
    audience: str
