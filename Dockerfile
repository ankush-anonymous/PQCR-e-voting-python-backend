# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies for OpenFHE and liboqs
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    g++ \
    git \
    libssl-dev \
    libgmp-dev \
    libmpfr-dev \
    pkg-config \
    python3-dev \
    curl && \
    rm -rf /var/lib/apt/lists/*

# Install OpenFHE
RUN git clone https://github.com/openfheorg/openfhe-development.git && \
    cd openfhe-development && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local && \
    make -j$(nproc) && \
    make install

# Set OpenFHE library path
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Copy the requirements file into the container
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

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

# Copy OpenFHE Encryption Code
COPY openfhe_encrypt.cpp /app/openfhe_encrypt.cpp

# Compile OpenFHE Encryption Code
RUN g++ /app/openfhe_encrypt.cpp -o /app/openfhe_encrypt -I/usr/local/include/openfhe -L/usr/local/lib -lopenfhe

# Copy the entire project directory into the container
COPY . .

# Expose the port your server runs on (8000 for FastAPI)
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Command to run your FastAPI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
