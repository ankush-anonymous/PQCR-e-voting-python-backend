from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.responses import JSONResponse
from app.oqs_wrapper import Signature  # Update this import for correct path
import uuid
import subprocess

# Initialize FastAPI app
app = FastAPI()

# Data Models (could be moved to schemas.py later for clarity)
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

class VoteRequest(BaseModel):
    candidate_id: str  # UUID of the selected candidate
    public_key: str
    signature: str
    voter_id: str


@app.get("/")
async def root():
    return {"message": "FastAPI Server is Running!"}

# 🔑 Generate post-quantum key pairs
@app.get("/generate-keypair", response_model=KeyPairResponse)
async def generate_keypair():
    try:
        sig = Signature("Dilithium5")
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        return {"public_key": public_key.hex(), "private_key": private_key.hex()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# 🔒 Authenticate voter
@app.post("/authenticate-voter")
async def authenticate_voter(request: AuthenticateRequest):
    try:
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
        raise HTTPException(status_code=500, detail=str(e))



# 🚀 FastAPI entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)