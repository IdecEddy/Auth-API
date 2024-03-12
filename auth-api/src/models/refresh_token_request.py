from pydantic import BaseModel


class RefreshTokenRequest(BaseModel):
    refreshToken: str
    audience: str
