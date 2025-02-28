from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.responses import JSONResponse
import subprocess
import base64

# Importing PQC Signature wrapper
from app.oqs_wrapper import Signature  # Ensure correct import

# Initialize FastAPI
app = FastAPI()

# 🔑 Data Models
class KeyPairResponse(BaseModel):
    public_key: str
    private_key: str

class AuthenticateRequest(BaseModel):
    public_key: str
    private_key: str
    voter_id: str

class VerifyRequest(BaseModel):
    public_key: str
    signature: str
    message: str

class VoteRequest(BaseModel):
    candidate_id: str
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

def verify_vote_signature(voter_public_key, candidate_id, voter_id, signature):
    # The original message that should have been signed
    message = candidate_id + voter_id

    # Verify signature
    sig = Signature("Dilithium5")
    return sig.verify(message.encode(), bytes.fromhex(signature), bytes.fromhex(voter_public_key))

@app.post("/submit-vote")
async def submit_vote(data: dict):
    try:
        candidate_id = data.get("candidate_id", "default_id")
        public_key = data.get("public_key", "default_key")
        signature = data.get("signature", "")
        voter_id = data.get("voter_id", "")

        # 🛑 Step 1: Verify the Signature Before Proceeding
        if not verify_vote_signature(public_key, candidate_id, voter_id, signature):
            raise HTTPException(status_code=403, detail="Invalid vote signature. Unauthorized vote.")

        # 🔐 Step 2: Encrypt the Vote
        result = subprocess.run(["/app/encrypt_vote", candidate_id], capture_output=True, text=True)

        if result.returncode != 0:
            raise HTTPException(status_code=500, detail="Encryption failed")

        # 📌 Step 3: Process C++ output to extract encrypted vote
        output_lines = result.stdout.strip().split("\n")
        encrypted_vote = None

        for i, line in enumerate(output_lines):
            if "=== ENCRYPTED VOTE DATA ===" in line and i + 1 < len(output_lines):
                encrypted_vote = output_lines[i + 1].strip()
                break

        if encrypted_vote is None:
            raise HTTPException(status_code=500, detail="Failed to extract encrypted vote from output")

        # ✅ Step 4: Return Encrypted Vote to Node.js Server
        return {
            "message": "Vote encrypted successfully.",
            "encrypted_vote": encrypted_vote
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 🚀 FastAPI entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
