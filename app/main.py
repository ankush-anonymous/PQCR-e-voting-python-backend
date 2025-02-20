from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.responses import JSONResponse
from oqs import Signature

app = FastAPI()

class KeyPairResponse(BaseModel):
    public_key: str
    private_key: str

class AuthenticateRequest(BaseModel):
    public_key: str
    private_key: str
    voter_id: str  # Unique identifier for the voter


class VerifyRequest(BaseModel):
    public_key: str
    signature: str
    message: str

@app.get("/generate-keypair", response_model=KeyPairResponse)
async def generate_keypair():
    """
    Generate a new Dilithium key pair (public and private keys).
    """
    try:
        sig = Signature("Dilithium5")
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        return {"public_key": public_key.hex(), "private_key": private_key.hex()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/authenticate-voter")
async def authenticate_voter(request: AuthenticateRequest):
    """
    Authenticate a voter by verifying their signature.
    """
    try:
        print("Received request:", request.dict())  # Debugging: Print request data
        
        public_key = bytes.fromhex(request.public_key)
        private_key = bytes.fromhex(request.private_key)
        voter_id = request.voter_id.encode()

        sig = Signature("Dilithium5", private_key)
        signature = sig.sign(voter_id)

        is_authentic = sig.verify(voter_id, signature, public_key)

        return {
            "is_authentic": is_authentic,
            "signature": signature.hex()
        }
    except Exception as e:
        print("Error in authentication:", str(e))  # Debugging
        raise HTTPException(status_code=500, detail=str(e))




if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)