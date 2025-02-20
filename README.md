# PQCR E-Voting Python Backend

This is a **Post-Quantum Cryptography (PQC) E-Voting backend** built using **FastAPI**, `liboqs`, and `Dilithium` for secure authentication. The server runs inside a **Docker container** for easy deployment.

---

## **🚀 Quick Start Guide**

### **1️⃣ Clone the Repository**

First, clone this GitHub repository to your local machine:

```sh
git clone https://github.com/YOUR_GITHUB_USERNAME/PQCR-e-voting-python-backend.git
```

Move into the project directory:

```sh
cd PQCR-e-voting-python-backend
```

---

### **2️⃣ Build the Docker Image**

Run the following command to **build the Docker container**:

```sh
docker build -t my-python-server .
```

---

### **3️⃣ Run the Container**

Once the image is built, start the server:

```sh
docker run -p 8000:8000 my-python-server
```

This will launch the FastAPI server inside Docker and make it available at:

```
http://localhost:8000/
```

---

## **🔍 API Endpoints**

| Method | Endpoint              | Description                                          |
| ------ | --------------------- | ---------------------------------------------------- |
| `GET`  | `/generate-keypair`   | Generate a Dilithium keypair (public & private key). |
| `POST` | `/authenticate-voter` | Authenticate a voter using Dilithium signatures.     |
| `POST` | `/verify-signature`   | Verify a signature using the public key.             |

---

## **📌 Example API Usage**

### **1️⃣ Generate a Keypair**

```sh
curl -X GET "http://localhost:8000/generate-keypair"
```

**Response:**

```json
{
  "public_key": "a1b2c3d4e5f6...",
  "private_key": "1a2b3c4d5e6f..."
}
```

### **2️⃣ Authenticate a Voter**

```sh
curl -X POST "http://localhost:8000/authenticate-voter" -H "Content-Type: application/json" -d '{
  "public_key": "a1b2c3d4e5f6...",
  "private_key": "1a2b3c4d5e6f...",
  "voter_id": "voter123"
}'
```

**Response:**

```json
{
  "is_authentic": true,
  "signature": "3f1a2b4c5d6e7f..."
}
```

### **3️⃣ Verify a Signature**

```sh
curl -X POST "http://localhost:8000/verify-signature" -H "Content-Type: application/json" -d '{
  "public_key": "a1b2c3d4e5f6...",
  "signature": "3f1a2b4c5d6e7f...",
  "message": "voter123"
}'
```

**Response:**

```json
{
  "is_valid": true
}
```

---

## **🛑 Stopping the Server**

To stop the running container:

```sh
docker ps  # Get the container ID
docker stop CONTAINER_ID
```

To remove the container:

```sh
docker rm CONTAINER_ID
```

---

## **🌍 Deploying on Cloud**

To deploy this Docker container on a cloud service like **AWS/GCP/Azure**:

1. Push your Docker image to Docker Hub:
   ```sh
   docker tag my-python-server YOUR_DOCKER_HUB_USERNAME/my-python-server
   docker push YOUR_DOCKER_HUB_USERNAME/my-python-server
   ```
2. Pull and run it on any cloud server:
   ```sh
   docker pull YOUR_DOCKER_HUB_USERNAME/my-python-server
   docker run -p 8000:8000 my-python-server
   ```

---

## **📜 License**

This project is licensed under the **MIT License**.

---

## **👨‍💻 Contributors**

- **Your Name** - [GitHub](https://github.com/YOUR_GITHUB_USERNAME)

---

## **📞 Need Help?**

Feel free to open an **issue** on GitHub or contact me! 🚀
