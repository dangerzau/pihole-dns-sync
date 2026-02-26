# -------------------------------------------------------------------
# builder stage: create a standalone binary using PyInstaller
# -------------------------------------------------------------------
FROM python:3.12 AS builder

# install build dependencies (and a few small tools for debugging)
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    iputils-ping \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
# install both runtime deps and pyinstaller
RUN pip install --no-cache-dir -r requirements.txt pyinstaller
COPY . .

# build single-file executable
RUN pyinstaller --onefile --name pihole-sync pihole_sync.py

# -------------------------------------------------------------------
# final runtime image: either Python-based or minimal binary-only
# -------------------------------------------------------------------
FROM python:3.12 AS runtime

# include Python for normal execution (default)
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENTRYPOINT ["python", "pihole_sync.py"]
CMD []

# lightweight image that just contains the compiled binary
# the runner image must contain a compatible glibc version; the
# binary is built against the Python 3.12 image (glibc ≥2.38), therefore we
# use the matching slim image rather than plain debian.
FROM python:3.12-slim AS runner

# include a few small networking utilities (ping, curl, nc) so that
# debugging and health‑check scripts can run inside the minimal image.
RUN apt-get update && apt-get install -y \
    iputils-ping \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/dist/pihole-sync /usr/local/bin/pihole-sync
# the binary expects to find its configuration in the same layout as
# the non-compiled version; mount /app or adjust as needed when running
ENTRYPOINT ["/usr/local/bin/pihole-sync"]
CMD []
