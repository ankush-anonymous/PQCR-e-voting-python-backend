# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies for liboqs and other libraries
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    libssl-dev \
    pkg-config && \
    rm -rf /var/lib/apt/lists/*

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

# Copy the entire project directory into the container
COPY . .

# Expose the port your server runs on
EXPOSE 5000

# Command to run your server
CMD ["python", "app/main.py"]