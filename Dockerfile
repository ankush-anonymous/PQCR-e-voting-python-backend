# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies for OpenFHE and liboqs
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    g++ \
    git \
    libssl-dev \
    libgmp-dev \
    libmpfr-dev \
    pkg-config \
    python3-dev \
    curl \
    wget && \
    rm -rf /var/lib/apt/lists/*

# Clone and Build OpenFHE (Using Your Method)
RUN git clone https://github.com/openfheorg/openfhe-development.git && \
    cd openfhe-development && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DWITH_EXAMPLES=OFF && \
    make -j$(nproc)

# Set OpenFHE Library Path (Your Method)
ENV LD_LIBRARY_PATH=/app/openfhe-development/build/lib

# Install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Clone and build liboqs
RUN git clone https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig  # Refresh the shared library cache

# Clone and install liboqs-python
RUN git clone https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && \
    pip install .

# Copy C++ encryption source code
COPY claude.cpp /app/claude.cpp

# Compile C++ encryption binary using OpenFHE build directory
RUN g++ -o /app/encrypt_vote /app/claude.cpp \
    -I/app/openfhe-development/src/core/include \
    -I/app/openfhe-development/src/pke/include \
    -I/app/openfhe-development/src/binfhe/include \
    -I/app/openfhe-development/build/src/core \
    -I/app/openfhe-development/third-party/cereal/include \
    -L/app/openfhe-development/build/lib \
    -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -std=c++17

# Ensure the compiled binary is executable
RUN chmod +x /app/encrypt_vote

# Copy the entire project directory into the container
COPY . .

# Expose the port your server runs on (8000 for FastAPI)
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run FastAPI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
