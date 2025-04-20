from pydantic import BaseModel
from typing import Optional


class TokenAuthRequest(BaseModel):
    authToken: Optional[str] = None
    refreshToken: Optional[str] = None
    audience: str
