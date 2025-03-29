import os
from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import base64
import json
from typing import List

# Importing PQC Signature wrapper
from app.oqs_wrapper import Signature  # Ensure correct import

# Ensure the folder exists before storing votes
ENCRYPTED_VOTES_DIR = "encrypted_votes"
Path(ENCRYPTED_VOTES_DIR).mkdir(parents=True, exist_ok=True)

MAPPING_DIR = "candidate_mappings"
os.makedirs(MAPPING_DIR, exist_ok=True)

app = FastAPI()

# 🔑 Data Models for existing endpoints
class DilithiumKeyPairResponse(BaseModel):
    voter_dilithium_public_key: str
    voter_dilithium_private_key: str

class AuthenticateVoterRequest(BaseModel):
    voter_dilithium_public_key: str
    voter_dilithium_private_key: str
    voter_id: str

class OpenFheKeygenRequest(BaseModel):
    election_id: str

class EncryptVoteRequest(BaseModel):
    candidate_id: str
    voter_id: str
    election_id: str

# 🔑 Data Models for vote proof endpoints
class GenerateVoteProofRequest(BaseModel):
    parameter_set: int
    voter_id: str

class GenerateVoteProofResponse(BaseModel):
    zkp_public_key: str
    zkp_proof: str

class VerifyVoteProofRequest(BaseModel):
    voter_id: str
    parameter_set: int
    zkp_public_key: str
    zkp_proof: str

class StoreMappingRequest(BaseModel):
    election_id: str
    mapping: dict

class Vote(BaseModel):
    encrypted_vote: str

class SaveEncrytVoteRequest(BaseModel):
    votes: List[Vote]



@app.get("/")
async def root():
    return {"message": "FastAPI Server is Running!"}

# 🔑 Generate post-quantum key pairs (existing endpoint)
@app.get("/generate-voter-dilithium-keypair", response_model=DilithiumKeyPairResponse)
async def generate_keypair():
    try:
        sig = Signature("Dilithium5")
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        # Correct the keys in the returned dict.
        return {
            "voter_dilithium_public_key": public_key.hex(), 
            "voter_dilithium_private_key": private_key.hex()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 🔒 Authenticate voter (existing endpoint)
@app.post("/authenticate-voter")
async def authenticate_voter(request: AuthenticateVoterRequest):
    try:
        # Use the field names defined in the model.
        public_key = bytes.fromhex(request.voter_dilithium_public_key)
        private_key = bytes.fromhex(request.voter_dilithium_private_key)
        voter_id = request.voter_id.encode()

        sig = Signature("Dilithium5", private_key)  
        signature = sig.sign(voter_id)

        is_authentic = sig.verify(voter_id, signature, public_key)

        return {
            "is_authentic": is_authentic,
            "voter_dilithium_signature": signature.hex()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
def verify_voter_signature(voter_public_key: str, voter_id: str, dilithium_signature: str) -> bool:
    """
    Verifies that the voter_id was correctly signed using Dilithium.
    
    Parameters:
      voter_public_key: Hex-encoded voter's public key.
      voter_id: The voter's identifier (used as the original message).
      dilithium_signature: Hex-encoded signature over the voter_id.
      
    Returns:
      True if the signature is valid, otherwise False.
    """
    message = voter_id
    sig = Signature("Dilithium5")
    return sig.verify(message.encode(), bytes.fromhex(dilithium_signature), bytes.fromhex(voter_public_key))

def parse_keygen_output(output: str):
    """
    Parses the output from the key-generation C++ binary.
    
    Expected output format (example):
        Keys generated successfully.
        Public Key (Base64):
        <public_key>
        
        Private Key (Base64):
        <private_key>
    
    Returns:
      A tuple (public_key, private_key) if found, otherwise (None, None).
    """
    try:
        lines = output.strip().split("\n")
        public_key = None
        private_key = None
        for i, line in enumerate(lines):
            if "Public Key (Base64):" in line and i + 1 < len(lines):
                public_key = lines[i + 1].strip()
            if "Private Key (Base64):" in line and i + 1 < len(lines):
                private_key = lines[i + 1].strip()
        return public_key, private_key
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
@app.post("/openfhe-keygen")
async def get_openfhe_keys(req: OpenFheKeygenRequest):
    """
    Generates OpenFHE keys by calling the key-generation binary.
    
    Steps:
      1. Call the key-generation binary (/app/encrypt_vote_keygen) to generate keys.
      2. Parse and return the Base64-encoded public and private OpenFHE keys.
      3. Create a temporary file (in the 'elections' folder) named using the election id,
         saving only the public key.
    
    Returns:
      A JSON object with keys "openfhe_public_key" and "openfhe_private_key".
    
    Raises:
      HTTPException if key generation, file creation, or parsing fails.
    """
    try:
        # Call the key-generation binary.
        result = subprocess.run(
            ["/app/encrypt_vote_keygen", req.election_id],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail="Key generation failed")
        
        # Parse the output for keys.
        public_key, private_key = parse_keygen_output(result.stdout)
        if not public_key or not private_key:
            raise HTTPException(
                status_code=500,
                detail="Failed to extract keys from key generation output"
            )
        
        # Create the elections folder if it doesn't exist.
        elections_folder = "elections"
        os.makedirs(elections_folder, exist_ok=True)
        
        # Create a temporary file using the election id as the filename,
        # and save only the public key.
        temp_file_path = os.path.join(elections_folder, f"{req.election_id}.tmp")
        with open(temp_file_path, "w") as temp_file:
            temp_file.write(f"openfhe_public_key: {public_key}\n")
        
        return {
            "openfhe_public_key": public_key,
            "openfhe_private_key": private_key
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

@app.post("/encrypt-vote") 
async def encrypt_vote(req: EncryptVoteRequest):
    """
    Encrypts a vote using one-hot encoding based on the candidate ID.
    """
    try:
        election_id = req.election_id
        voter_id = req.voter_id
        candidate_id = req.candidate_id

        # Step 1: Load candidate mapping from JSON file
        mapping_file_path = os.path.join(MAPPING_DIR, f"{election_id}.json")
        if not os.path.exists(mapping_file_path):
            raise HTTPException(status_code=500, detail="Candidate mapping file not found")

        with open(mapping_file_path, "r") as file:
            candidate_mapping = json.load(file)

        # Step 2: Create a one-hot encoded vector
        num_candidates = len(candidate_mapping)
        one_hot_vector = [0] * num_candidates

        if candidate_id not in candidate_mapping:
            raise HTTPException(status_code=400, detail="Invalid candidate ID")

        candidate_index = candidate_mapping[candidate_id]
        one_hot_vector[candidate_index] = 1

        print(f"✅ One-hot vector for candidate '{candidate_id}': {one_hot_vector}")

        # Step 3: Define the public key path correctly
        elections_folder = "elections"
        public_key_path = os.path.join(elections_folder, f"{election_id}_public_key.tmp")
        if not os.path.exists(public_key_path):
            raise HTTPException(status_code=500, detail="Election file not found")

        # Step 4: Convert vector to string and call encryption binary
        vector_str = " ".join(map(str, one_hot_vector))
        result = subprocess.run(
            ["/app/encrypt_vote", vector_str, req.election_id],
            capture_output=True,
            text=True
        )

        print(f"Command return code: {result.returncode}")
        print(f"Command stdout: {result.stdout}")
        print(f"Command stderr: {result.stderr}")

        if result.returncode != 0:
            raise HTTPException(
                status_code=500, 
                detail=f"Encryption failed: {result.stderr}"
            )

        # Step 5: Extract the encrypted vote from C++ output
        output_lines = result.stdout.strip().split("\n")
        encrypted_vote = None
        for i, line in enumerate(output_lines):
            if "=== ENCRYPTED VOTE DATA ===" in line and i + 1 < len(output_lines):
                encrypted_vote = output_lines[i + 1].strip()
                break

        if not encrypted_vote:
            raise HTTPException(status_code=500, detail="Failed to extract encrypted vote")

        # Step 6: Save the encrypted vote to a file
        file_path = os.path.join(ENCRYPTED_VOTES_DIR, f"{voter_id}.txt")
        with open(file_path, "w") as file:
            file.write(encrypted_vote)

        # Return the response
        return {
            "message": "Vote encrypted successfully using one-hot encoding.",
            "one_hot_vector": one_hot_vector,
            "encrypted_vote": encrypted_vote,
            "file_path": file_path
        }

    except Exception as e:
        print(f"Error in encrypt_vote: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/store-candidate-mapping")
async def store_mapping(request: StoreMappingRequest):
    try:
        # Extract data from request model
        election_id = request.election_id
        mapping = request.mapping

        # Define file path
        file_path = os.path.join(MAPPING_DIR, f"{election_id}.json")

        # Store mapping as JSON
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(mapping, f, indent=4)

        return {
            "message": "Candidate mapping stored successfully",
            "election_id": election_id
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# New Endpoint: Generate Vote Proof using Picnic (ZKP)
@app.post("/generate-vote-proof", response_model=GenerateVoteProofResponse)
async def generate_vote_proof_endpoint(req: GenerateVoteProofRequest):
    try:
        # Step 1: Locate the encrypted vote file.
        file_path = os.path.join(ENCRYPTED_VOTES_DIR, f"{req.voter_id}.txt")
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Encrypted vote file not found.")

        print(f"Using encrypted vote file: {file_path}")

        # Step 2: Generate proof using the Picnic ZKP binary.
        cmd = ["/app/voting_proof", "gen", str(req.parameter_set), file_path]
        result = subprocess.run(cmd, capture_output=True, text=True)

        print(f"Subprocess stdout:\n{result.stdout}")
        print(f"Subprocess stderr:\n{result.stderr}")

        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Error generating vote proof: {result.stderr}")

        # Step 3: Extract public key and proof from output (look for Base64 labels).
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

        return GenerateVoteProofResponse(zkp_public_key=pubkey_hex, zkp_proof=proof_hex)

    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Error generating vote proof: {e.stderr}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify-vote-proof")
async def verify_vote_proof_endpoint(req: VerifyVoteProofRequest):
    try:
        # Step 1: Locate the encrypted vote file.
        file_path = os.path.join(ENCRYPTED_VOTES_DIR, f"{req.voter_id}.txt")
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Encrypted vote file not found.")

        print(f"Using encrypted vote file for verification: {file_path}")

        # Command to verify proof: voting_proof verify.
        cmd = [
            "/app/voting_proof", "verify", str(req.parameter_set),
            file_path, req.zkp_public_key, req.zkp_proof
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
    
@app.post("/receive-votes")
async def receive_votes_from_node_server(req: SaveEncrytVoteRequest):
    """
    Receives votes in JSON format and saves them to a file.

    The request is validated using the SaveEncrytVoteRequest model.
    Votes are saved into a JSON file under the "tally_votes" folder.

    Returns:
        A JSON response with a success message and the file path.

    Raises:
        HTTPException: If any error occurs during file writing.
    """
    try:
        # Log for debugging purposes
        # print("Function called with votes:", req.votes)

        # Create the folder if it doesn't exist (using underscore to avoid spaces)
        folder_name = "tally_votes"
        os.makedirs(folder_name, exist_ok=True)
        
        # Define the file path (you could incorporate an election id if needed)
        file_path = os.path.join(folder_name, "encrypted_votes.json")
        
        # Convert list of Vote objects to list of dictionaries
        votes_data = [vote.dict() for vote in req.votes]
        
        # Write the votes to the JSON file with indentation for readability
        with open(file_path, "w") as json_file:
            json.dump({"votes": votes_data}, json_file, indent=4)
        
        print("Votes saved to:", file_path)
        return {"message": "Votes saved successfully", "file_path": file_path}
    except Exception as e:
        print("Error encountered:", str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/aggregate-votes")
async def aggregate_votes():
    """
    Aggregates votes by sending the file path to the C++ aggregator executable.
    
    The process is as follows:
      1. Construct the file path from the provided election_id.
      2. Check if the file exists.
      3. Call the C++ executable "./vote_aggregator" with the file path as an argument.
      4. Capture and return the final aggregated cipher text.
    
    Returns:
        A JSON object with the aggregated cipher text.
    
    Raises:
        HTTPException: If the file does not exist or if the C++ aggregator fails.
    """
    try:
        # Construct the file path where votes are stored
        folder_name = "tally_votes"
        file_path = os.path.join(folder_name, f"encrypted_votes.json")
        
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail=f"Encrypted Votes File not found ")
        
        # Call the C++ aggregator executable with the file path argument
        result = subprocess.run(
            ["./vote_aggregator", file_path],
            capture_output=True,
            text=True
        )
        
        # Check if the C++ process executed successfully
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Aggregator failed: {result.stderr}")
        
        # Strip any extra whitespace/newlines from the output
        aggregated_cipher_text = result.stdout.strip()
        
        return {
            "message": "Aggregation successful",
            "aggregated_cipher_text": aggregated_cipher_text
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# 🚀 FastAPI entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
