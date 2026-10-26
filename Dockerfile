# ============================================================
# CyberRecon — Multi-Stage Dockerfile
# ============================================================
# Stage 1 (builder): install Python deps into a venv
# Stage 2 (runtime): copy venv + source into slim image
#
# Debian 13 (trixie) compatibility note:
#   - libgl1-mesa-glx was renamed to libgl1
#   - This image tracks python:3.11-slim which is now based on trixie
# ============================================================

# ---------- Stage 1: builder ----------
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build-only dependencies (compilers for wheels without prebuilts)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create virtualenv
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ---------- Stage 2: runtime ----------
FROM python:3.11-slim AS runtime

# Install runtime-only system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # OpenCV runtime (Debian 13: libgl1-mesa-glx → libgl1)
    libgl1 \
    libglib2.0-0 \
    # QR decoding (in case pyzbar is used)
    libzbar0 \
    # curl for healthcheck
    curl \
    # Chrome installation prerequisites
    wget gnupg ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Google Chrome (headless) for Selenium-based QR visual channel
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub \
        | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" \
        > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*

# Copy the venv from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Copy application source
COPY . .

# Non-root user
RUN useradd -m -u 1000 recon && chown -R recon:recon /app
USER recon

# Metadata
LABEL org.opencontainers.image.title="CyberRecon C2 Server" \
      org.opencontainers.image.description="QR-Code-Based C2 Framework (educational research)" \
      org.opencontainers.image.source="https://github.com/Jeevan1725/cyberrecon" \
      org.opencontainers.image.licenses="MIT"

# Expose C2 port
EXPOSE 8443

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8443/check || exit 1

# Default: run C2 server
CMD ["python", "c2_server.py"]