📦 Pihole-Dns-Sync
Automated Pi-hole v6 DNS Record Management for Docker Containers

Pihole-Dns-Sync is a lightweight tool that listens for Docker container events and automatically syncs container DNS records with your Pi-hole v6 instance. It supports both Traefik labels and manual container environment variables to manage A and CNAME records dynamically.

✨ Features
🐳 Listens to container start/stop events
🔖 Reads Traefik Host() labels or custom environment variables
🛡️ Adds A or CNAME records to Pi-hole v6 automatically
🧹 Removes DNS records when containers stop
🧪 Dry-run mode for safe testing
📈 Exposes Prometheus metrics
🔥 Extremely lightweight and fast (Python + Docker SDK)
⚙️ Environment Variables

Variable	Required	Default	Description
PIHOLE_URL	✅	—	Full URL (e.g., http://192.168.1.10) or IP address of Pi-hole (must include `/api/` suffix) and can use the docker service name ie http://pihole/api
PIHOLE_PASSWORD	✅	—	Pi-hole web interface api password (used to obtain a session)
DEFAULT_DNS_TARGET	❌	—	Default target IP or host if using Traefik mode
TRAEFIK_WATCH	❌	true	Whether to watch Traefik labels (true) or manual vars (false)
DRY_RUN	❌	false	If true, no changes are made to Pi-hole (simulates only)
RECONCILE_INTERVAL_MINUTES	❌	0	If set to >0, the service will automatically re-run reconciliation every N minutes
HEALTHCHECK_PORT	❌	8000	Port for internal healthcheck server
STATE_FILE	❌	pihole_state.json	Path inside the container where persistent state is stored
SCAN_ON_START	❌	false	If true, perform a full `--scan` audit immediately at startup
WAIT_FOR	❌	—	Comma-separated list of container names to wait for healthy before starting
WAIT_TIMEOUT_SECONDS	❌	0	Maximum seconds to wait for dependencies (0=infinite)
mapping1 to mapping99	❌	—	Global static DNS mappings in format `sourceaddress,destinationaddress` (see Global DNS Mappings section)
🐳 Docker Compose Example
yaml
Copy
Edit
version: '3.9'

services:
  pihole-dns-sync:
    image: ghcr.io/dangerzau/pihole-dns-sync:latest
    container_name: pihole-dns-sync
    restart: unless-stopped
    environment:
      - PIHOLE_URL=http://192.168.1.10/api/
      - PIHOLE_PASSWORD=your_pihole_password_here
      - TRAEFIK_WATCH=true
      - DEFAULT_DNS_TARGET=192.168.1.100
      - DRY_RUN=false
      - RECONCILE_INTERVAL_MINUTES=30   # optional: Re-sync every 30 minutes - Set in minutes - Can be handy if services take a while to come up and got missed during boot
      - SCAN_ON_START=true             # run container scan on startup - Handy if containers are being missed during a reboot - If you set Pihole-Dns-Sync to be the last container to startup, this option is for you
      - WAIT_FOR=traefik,pihole        # wait for these to report healthy
      - WAIT_TIMEOUT_SECONDS=60        # give up after one minute
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      # persist state so records survive container restarts
      - ./data:/data
    environment:
      - STATE_FILE=/data/pihole_state.json
    ports:
      - 8000:8000
🔥 Manual Mode (Without Traefik)
If TRAEFIK_WATCH=false, each container you want to sync must define two environment variables:
Container Env Variable	Description
CONTAINER_HOST	The hostname to register
TARGET_HOST	The IP address or hostname the record points to

🌍 Global DNS Mappings
In addition to container-based DNS records, you can define global static DNS mappings that apply to all containers. These are useful for permanent cross-service references and are specified via environment variables.

**Format:** Define environment variables named `mapping1`, `mapping2`, ... up to `mapping99` with the format:
```
mapping<N>=sourceaddress,destinationaddress
```

**Examples:**
```
mapping1=abs.jimmyc.net,jf.jimmyc.net       # Creates CNAME record
mapping2=radarr.jimmyc.net,192.168.1.100    # Creates A record (IP address)
mapping3=sonarr.example.com,arr.internal    # Creates CNAME record
```

**How it works:**
- The tool automatically detects if `destinationaddress` is an IP address
  - **If IP address:** Creates an A record pointing to that IP
  - **If hostname/FQDN:** Creates a CNAME record pointing to that hostname
- Global mappings are applied at startup and during periodic reconciliation
- They persist independently of container lifecycle events

🔄 How It Works

Each container you want to have dns records automatically configured needs the to have the the following labels set
Labels:
  - "piholeup=true"
  - "traefik.http.routers.somerouter.rule=Host(`somesubdomain.mydomain.net`)

Without the piholeup=true label pihole-dns-sync will ignore the host records and NOT create dns records automatically.

On container start:

If TRAEFIK_WATCH=true, reads the Host() rule from Traefik label.
If TRAEFIK_WATCH=false, reads CONTAINER_HOST and TARGET_HOST.
Creates either an A record (if target is IP) or a CNAME record (if target is hostname).
On container stop:
Automatically deletes the record from Pi-hole.


🔧 Local Development
Clone and build:

bash
Copy
Edit
git clone https://github.com/dangerzau/pihole-dns-sync.git
cd pihole-dns-sync
docker-compose build
docker-compose up

📘 **Command‑line mode**
You can also run the image just once to scan your existing containers and
re‑create any DNS records.  This is handy when invoked from another stack or
a periodic cron job.  Example:

```sh
# one‑time scan; every discovered record will be pushed to Pi-hole even if
# the service has previously seen it

docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e PIHOLE_URL=http://192.168.1.10/api/ \
  -e PIHOLE_PASSWORD=secret \
  ghcr.io/dangerzau/pihole-dns-sync:latest --scan

# (the --force flag still exists but has no effect; it is retained for
# backwards compatibility)
```
The container will perform the audit then exit immediately.

> Alternatively, if you already have a running `pihole-dns-sync` service,
> you can exec into it rather than starting a new container:
>
> ```sh
> docker exec pihole-dns-sync python /app/pihole_sync.py --scan
> ```
>
> 
> ### Building a standalone binary
> The project can be compiled with [PyInstaller](https://www.pyinstaller.org/)
> so that you no longer need a Python interpreter in the final image.
>
> ```sh
> pip install pyinstaller
> pyinstaller --onefile --name pihole-sync pihole_sync.py
> # result goes in dist/pihole-sync
> ```
>
> A multi‑stage Dockerfile is provided; to build an image that contains only
> the binary use:
>
> ```sh
> docker build --target=runner -t pihole-dns-sync:binary .
> ```
>
> The resulting container is tiny and simply runs `/usr/local/bin/pihole-sync`.
> It behaves identically to the scripted version, but does not require Python
> being installed at runtime.  **Note:** the binary is built against the same
> Python 3.12 base image, so the runner image uses `python:3.12-slim` to
> ensure the underlying glibc is new enough (≥2.38) – attempting to run it on
> older distributions may produce `GLIBC` errors.
>
> **Note:** the `runner` image also includes a few small networking utilities
> (`ping`, `curl`, `nc`) so you have basic troubleshooting tools even though the
> image is otherwise minimal.


🎯 Notes
Works best with Pi-hole v6 (which introduced API support for DNS records)

Designed for homelab setups, media servers, internal apps, and self-hosted services

📣 Contributing
Pull requests and suggestions are welcome! Feel free to open an issue if you find a bug or want a feature added.



