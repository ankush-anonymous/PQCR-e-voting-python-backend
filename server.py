from fastapi import FastAPI, HTTPException
import subprocess

app = FastAPI()

@app.post("/submit-vote")
async def submit_vote(data: dict):
    try:
        candidate_id = data.get("candidate_id", "default_id")
        public_key = data.get("public_key", "default_key")
        signature = data.get("signature", "")
        voter_id = data.get("voter_id", "")

        # Run the C++ encryption binary with candidate_id
        result = subprocess.run(["/app/encrypt_vote", candidate_id], capture_output=True, text=True)

        if result.returncode != 0:
            raise HTTPException(status_code=500, detail="Encryption failed")

        # Process C++ output to extract the encrypted vote
        output_lines = result.stdout.strip().split("\n")
        encrypted_vote = None

        for i, line in enumerate(output_lines):
            if "=== ENCRYPTED VOTE DATA ===" in line and i + 1 < len(output_lines):
                encrypted_vote = output_lines[i + 1].strip()  # The actual encrypted data is the next line
                break

        if encrypted_vote is None:
            raise HTTPException(status_code=500, detail="Failed to extract encrypted vote from output")

        return {
            "message": "Vote submitted successfully.",
            "encrypted_vote": encrypted_vote
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
