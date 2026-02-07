# ============================================================
# TSUNAMI v3.0 - Production Dockerfile
# Global-Scale Cyber Intelligence Platform
# ============================================================

FROM python:3.12-slim-bookworm

LABEL maintainer="TSUNAMI Security Team"
LABEL version="3.0.0"
LABEL description="Global-Scale Cyber Intelligence Platform"

# Security: Run as non-root user
ENV TSUNAMI_USER=tsunami
ENV TSUNAMI_UID=1000
ENV TSUNAMI_GID=1000

# Create tsunami user and group
RUN groupadd -g ${TSUNAMI_GID} ${TSUNAMI_USER} && \
    useradd -u ${TSUNAMI_UID} -g ${TSUNAMI_GID} -m -s /bin/bash ${TSUNAMI_USER}

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools
    build-essential \
    gcc \
    g++ \
    # Network tools
    curl \
    wget \
    nmap \
    dnsutils \
    whois \
    traceroute \
    tcpdump \
    netcat-openbsd \
    # Geospatial dependencies
    libgdal-dev \
    libgeos-dev \
    libproj-dev \
    # Security tools
    openssl \
    ca-certificates \
    # Other
    git \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=${TSUNAMI_USER}:${TSUNAMI_USER} . .

# Create necessary directories
RUN mkdir -p /var/lib/tsunami /var/log/tsunami /var/lib/tsunami/uploads /var/lib/tsunami/exports && \
    chown -R ${TSUNAMI_USER}:${TSUNAMI_USER} /var/lib/tsunami /var/log/tsunami

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV TSUNAMI_ENV=production
ENV TSUNAMI_DB_PATH=/var/lib/tsunami/dalga.db

# Switch to non-root user
USER ${TSUNAMI_USER}

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/api/saglik || exit 1

# Default command
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "--threads", "2", \
     "--worker-class", "eventlet", "--timeout", "120", "--keep-alive", "5", \
     "--access-logfile", "/var/log/tsunami/access.log", \
     "--error-logfile", "/var/log/tsunami/error.log", \
     "--capture-output", "--enable-stdio-inheritance", \
     "dalga_web:app"]
