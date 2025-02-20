from pydantic import BaseModel

class KeyPairResponse(BaseModel):
    public_key: str
    private_key: str