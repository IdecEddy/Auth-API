from pydantic import BaseModel


class TokenAuthRequest(BaseModel):
    authToken: str
    refreshToken: str
    audience: str
