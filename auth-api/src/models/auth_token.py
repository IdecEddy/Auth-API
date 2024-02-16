from pydantic import BaseModel


class AuthToken(BaseModel):
    token: str
    audience: str
