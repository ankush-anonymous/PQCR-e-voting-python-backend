# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies (added nlohmann-json3-dev to install the missing header)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \           
    cmake \
    g++ \
    git \
    libssl-dev \
    libgmp-dev \
    libmpfr-dev \
    libboost-all-dev \
    pkg-config \
    python3-dev \
    curl \
    wget \
    ninja-build \
    libsodium-dev \
    nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*


# ============================
# 📌 Install OpenFHE
# ============================
RUN git clone https://github.com/openfheorg/openfhe-development.git && \
    cd openfhe-development && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DWITH_EXAMPLES=OFF && \
    make -j$(nproc) && \
    make install

# Set OpenFHE Library Path
ENV LD_LIBRARY_PATH=/usr/local/lib

# ============================
# 📌 Install liboqs (Post-Quantum Cryptography)
# ============================
RUN git clone --branch main https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Install liboqs-python
RUN git clone https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && \
    pip install .

# ============================
# 📌 Install Python Dependencies
# ============================
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# ============================
# 📌 Copy the Entire Project Directory
# ============================
COPY . .

# ============================
# 📌 Compile C++ OpenFHE Encryption Binary
# ============================
RUN g++ -o /app/encrypt_vote_keygen /app/encrypt_vote_keygen.cpp \
    -I/app/openfhe-development/src/core/include \
    -I/app/openfhe-development/src/pke/include \
    -I/app/openfhe-development/src/binfhe/include \
    -I/app/openfhe-development/build/src/core \
    -I/app/openfhe-development/third-party/cereal/include \
    -L/app/openfhe-development/build/lib \
    -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -std=c++17

RUN g++ -o /app/encrypt_vote /app/encrypt_vote.cpp \
    -I/app/openfhe-development/src/core/include \
    -I/app/openfhe-development/src/pke/include \
    -I/app/openfhe-development/src/binfhe/include \
    -I/app/openfhe-development/build/src/core \
    -I/app/openfhe-development/third-party/cereal/include \
    -L/app/openfhe-development/build/lib \
    -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -std=c++17

RUN g++ -o /app/vote_aggregator /app/aggregator.cpp \
    -I/app/openfhe-development/src/core/include \
    -I/app/openfhe-development/src/pke/include \
    -I/app/openfhe-development/src/binfhe/include \
    -I/app/openfhe-development/build/src/core \
    -I/app/openfhe-development/third-party/cereal/include \
    -I/app/openfhe-development/src/core/include/serialization \
    -I/app/openfhe-development/src/pke/include/serialization \
    -L/app/openfhe-development/build/lib \
    -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -std=c++17

# RUN g++ -o /app/decrypt_vote /app/decrypt_vote.cpp \
#     -I/app/openfhe-development/src/core/include \
#     -I/app/openfhe-development/src/pke/include \
#     -I/app/openfhe-development/src/binfhe/include \
#     -I/app/openfhe-development/build/src/core \
#     -I/app/openfhe-development/third-party/cereal/include \
#     -L/app/openfhe-development/build/lib \
#     -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -std=c++17

# ============================
# 📌 Clone and Build Picnic (Picnic-based ZKP)
# ============================
# Clone the Picnic repository into /app/picnic
RUN git clone https://github.com/microsoft/Picnic.git /app/picnic

# Build the Picnic library so that libpicnic.a and libshake.a are produced.
RUN cd /app/picnic && make -j$(nproc) CFLAGS+='-Wno-error=stringop-overflow -D__LINUX__ -D__X64__'

# ============================
# 📌 Compile C++ Voting Proof Binary (Picnic-based ZKP)
# ============================
# Copy your voting proof C source file (voting_proof.c) into /app
COPY voting_proof.c /app/voting_proof.c
RUN gcc -O2 -D__LINUX__ -D__X64__ -Wno-error=stringop-overflow \
    -I/app/picnic \
    /app/voting_proof.c -o /app/voting_proof \
    -L/app/picnic -lpicnic -L/app/picnic/sha3 -lshake \
    -lssl -lcrypto


# Expose the FastAPI port
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run FastAPI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
