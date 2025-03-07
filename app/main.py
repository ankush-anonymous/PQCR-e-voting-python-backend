import os
from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import base64

# Importing PQC Signature wrapper
from app.oqs_wrapper import Signature  # Ensure correct import

# Ensure the folder exists before storing votes
ENCRYPTED_VOTES_DIR = "encrypted_votes"
Path(ENCRYPTED_VOTES_DIR).mkdir(parents=True, exist_ok=True)

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
    voter_id: str

class GenerateVoteProofResponse(BaseModel):
    public_key_hex: str
    proof_hex: str

class VerifyVoteProofRequest(BaseModel):
    voter_id: str
    parameter_set: int
    public_key_base64: str
    proof_base64: str

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

        # 📝 Step 4: Save Encrypted Vote to a File
        file_path = os.path.join(ENCRYPTED_VOTES_DIR, f"{voter_id}.txt")
        with open(file_path, "w") as file:
            file.write(encrypted_vote)

        # ✅ Step 5: Return Response
        return {
            "message": "Vote encrypted successfully. File saved.",
            "encrypted_vote": encrypted_vote,
            "file_path": file_path
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# New Endpoint: Generate Vote Proof using Picnic (ZKP)
@app.post("/generate-vote-proof", response_model=GenerateVoteProofResponse)
async def generate_vote_proof_endpoint(req: GenerateVoteProofRequest):
    try:
        # Step 1: Locate the encrypted vote file
        file_path = os.path.join(ENCRYPTED_VOTES_DIR, f"{req.voter_id}.txt")
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Encrypted vote file not found.")

        print(f"Using encrypted vote file: {file_path}")

        # Step 2: Generate proof using the Picnic ZKP binary
        cmd = ["/app/voting_proof", "gen", str(req.parameter_set), file_path]
        result = subprocess.run(cmd, capture_output=True, text=True)

        print(f"Subprocess stdout:\n{result.stdout}")
        print(f"Subprocess stderr:\n{result.stderr}")

        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Error generating vote proof: {result.stderr}")

        # Step 3: Extract public key and proof from output (look for Base64 labels)
        pubkey_hex = None
        proof_hex = None
        lines = result.stdout.strip().splitlines()

        for i, line in enumerate(lines):
            if "Serialized public key (Base64):" in line and i + 1 < len(lines):
                pubkey_hex = lines[i + 1].strip()
            if "Generated ZKP proof (Base64):" in line and i + 1 < len(lines):
                proof_hex = lines[i + 1].strip()

        if not pubkey_hex or not proof_hex:
            raise HTTPException(status_code=500, detail="Failed to parse output from voting_proof binary.")

        return GenerateVoteProofResponse(public_key_hex=pubkey_hex, proof_hex=proof_hex)

    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Error generating vote proof: {e.stderr}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.post("/verify-vote-proof")
async def verify_vote_proof_endpoint(req: VerifyVoteProofRequest):
    try:
        # Step 1: Locate the encrypted vote file
        file_path = os.path.join(ENCRYPTED_VOTES_DIR, f"{req.voter_id}.txt")
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Encrypted vote file not found.")

        print(f"Using encrypted vote file for verification: {file_path}")

        # Command to verify proof: voting_proof verify
        cmd = [
            "/app/voting_proof", "verify", str(req.parameter_set),
            file_path, req.public_key_base64, req.proof_base64
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        if "Proof verification succeeded" in result.stdout:
            # Delete the file after successful verification.
            try:
                os.remove(file_path)
                print(f"Deleted encrypted vote file: {file_path}")
            except Exception as del_err:
                print(f"Warning: Failed to delete file {file_path}: {del_err}")
            return {"message": "Proof verification succeeded. The vote is valid and the file has been deleted."}
        else:
            raise Exception("Proof verification did not return a success message.")
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Error verifying vote proof: {e.stderr}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    

# 🚀 FastAPI entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
