from pydantic import BaseModel

class AuthTokenRequest(BaseModel):
    authToken: str
    audience: str
