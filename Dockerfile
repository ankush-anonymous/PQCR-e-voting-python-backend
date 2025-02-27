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
    curl \
    wget && \
    rm -rf /var/lib/apt/lists/*

# Install Cereal Library (Required by OpenFHE)
RUN mkdir -p /usr/local/include/cereal && \
    wget -qO- https://github.com/USCiLab/cereal/archive/refs/tags/v1.3.0.tar.gz | tar xz && \
    cp -r cereal-1.3.0/include/cereal /usr/local/include/ && \
    rm -rf cereal-1.3.0

# Copy requirements first to use cached layers for Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Clone and install liboqs (cached unless changed)
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig  # Refresh shared library cache

# Clone and install liboqs-python (cached unless changed)
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && \
    pip install .

# **STEP 1: Keep OpenFHE installation cached separately**
RUN git clone --depth 1 https://github.com/openfheorg/openfhe-development.git && \
    cd openfhe-development && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local && \
    make -j$(nproc) && \
    make install

# Set OpenFHE library path
ENV LD_LIBRARY_PATH=/usr/local/lib

# **STEP 2: Only copy and compile your new C++ file (so this step gets rebuilt only when changed)**
COPY openfhe_encrypt.cpp /app/openfhe_encrypt.cpp
RUN g++ /app/openfhe_encrypt.cpp -o /app/openfhe_encrypt \
    -I/usr/local/include/openfhe/pke \
    -I/usr/local/include/openfhe/core \
    -I/usr/local/include/openfhe/binfhe \
    -I/usr/local/include/cereal \
    -L/usr/local/lib -lopenfhe

# Copy the rest of your project
COPY . .

# Expose the port your server runs on (8000 for FastAPI)
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Command to run your FastAPI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
