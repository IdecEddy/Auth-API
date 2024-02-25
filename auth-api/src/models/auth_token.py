from pydantic import BaseModel


class AuthToken(BaseModel):
    refreshToken: str
    authToken: str
    audience: str
