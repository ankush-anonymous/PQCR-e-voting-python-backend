from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import base64

# Importing PQC Signature wrapper
from app.oqs_wrapper import Signature  # Ensure correct import

app = FastAPI()

# 🔑 Data Models for existing endpoints
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

# 🔑 Data Models for vote proof endpoints
class GenerateVoteProofRequest(BaseModel):
    parameter_set: int
    encrypted_vote: str

class GenerateVoteProofResponse(BaseModel):
    public_key_hex: str
    proof_hex: str

class VerifyVoteProofRequest(BaseModel):
    parameter_set: int
    encrypted_vote: str
    public_key_hex: str
    proof_hex: str

@app.get("/")
async def root():
    return {"message": "FastAPI Server is Running!"}

# 🔑 Generate post-quantum key pairs (existing endpoint)
@app.get("/generate-keypair", response_model=KeyPairResponse)
async def generate_keypair():
    try:
        sig = Signature("Dilithium5")
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        return {"public_key": public_key.hex(), "private_key": private_key.hex()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 🔒 Authenticate voter (existing endpoint)
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
    message = voter_id
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

# New Endpoint: Generate Vote Proof using Picnic (ZKP)
@app.post("/generate-vote-proof", response_model=GenerateVoteProofResponse)
async def generate_vote_proof_endpoint(req: GenerateVoteProofRequest):
    try:
        # Command to generate proof: /app/voting_proof gen <parameter_set> "<encrypted_vote>"
        cmd = ["/app/voting_proof", "gen", str(req.parameter_set), req.encrypted_vote]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Parse the output to extract public key hex and proof hex.
        # Expected output lines:
        #   "Serialized public key (hex):" followed by the key on the next line.
        #   "Generated ZKP proof (hex):" followed by the proof on the next line.
        pubkey_hex = None
        proof_hex = None
        lines = result.stdout.strip().splitlines()
        for i, line in enumerate(lines):
            if "Serialized public key (hex):" in line and i + 1 < len(lines):
                pubkey_hex = lines[i + 1].strip()
            if "Generated ZKP proof (hex):" in line and i + 1 < len(lines):
                proof_hex = lines[i + 1].strip()
        if not pubkey_hex or not proof_hex:
            raise Exception("Failed to parse output from voting_proof binary.")
        return GenerateVoteProofResponse(public_key_hex=pubkey_hex, proof_hex=proof_hex)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Error generating vote proof: {e.stderr}")

# New Endpoint: Verify Vote Proof using Picnic (ZKP)
@app.post("/verify-vote-proof")
async def verify_vote_proof_endpoint(req: VerifyVoteProofRequest):
    try:
        # Command to verify proof: /app/voting_proof verify <parameter_set> "<encrypted_vote>" "<public_key_hex>" "<proof_hex>"
        cmd = [
            "/app/voting_proof", "verify", str(req.parameter_set),
            req.encrypted_vote, req.public_key_hex, req.proof_hex
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if "Proof verification succeeded" in result.stdout:
            return {"message": "Proof verification succeeded. The vote is valid."}
        else:
            raise Exception("Proof verification did not return a success message.")
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Error verifying vote proof: {e.stderr}")

# 🚀 FastAPI entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
