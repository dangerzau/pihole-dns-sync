📦 pihole-dns-sync
Automated Pi-hole v6 DNS Record Management for Docker Containers

pihole-dns-sync is a lightweight tool that listens for Docker container events and automatically syncs container DNS records with your Pi-hole v6 instance. It supports both Traefik labels and manual container environment variables to manage A and CNAME records dynamically.

✨ Features
🐳 Listens to container start/stop events

🔖 Reads Traefik Host() labels or custom environment variables

🛡️ Adds A or CNAME records to Pi-hole v6 automatically

🧹 Removes DNS records when containers stop

🧪 Dry-run mode for safe testing

📈 Exposes Prometheus metrics

💚 Healthcheck HTTP server for monitoring

🔥 Extremely lightweight and fast (Python + Docker SDK)

⚙️ Environment Variables

Variable	Required	Default	Description
PIHOLE_URL	✅	—	Full URL (e.g., http://192.168.1.10) or IP address of Pi-hole
PIHOLE_TOKEN	✅	—	Pi-hole API token
TRAEFIK_WATCH	❌	true	Whether to watch Traefik labels (true) or manual vars (false)
TARGET	❌	—	Default target IP or host if using Traefik mode
DRY_RUN	❌	false	If true, no changes are made to Pi-hole (simulates only)
HEALTHCHECK_PORT	❌	8000	Port for internal healthcheck server
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
      - PIHOLE_URL=http://192.168.1.10
      - PIHOLE_TOKEN=your_pihole_token_here
      - TRAEFIK_WATCH=true
      - TARGET=192.168.1.100
      - DRY_RUN=false
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    ports:
      - 8000:8000
🔥 Manual Mode (Without Traefik)
If TRAEFIK_WATCH=false, each container you want to sync must define two environment variables:


Container Env Variable	Description
CONTAINER_HOST	The hostname to register
TARGET_HOST	The IP address or hostname the record points to
🔄 How It Works
On container start:

If TRAEFIK_WATCH=true, reads the Host() rule from Traefik label.

If TRAEFIK_WATCH=false, reads CONTAINER_HOST and TARGET_HOST.

Creates either an A record (if target is IP) or a CNAME record (if target is hostname).

On container stop:

Automatically deletes the record from Pi-hole.

📈 Prometheus Metrics
Available on http://localhost:8000/metrics, includes:

Number of created records

Number of deleted records

API call success/failure counts

💚 Healthcheck
Simple health endpoint at:

http
Copy
Edit
GET http://localhost:8000/health
Returns HTTP 200 OK if the service is running.

🔧 Local Development
Clone and build:

bash
Copy
Edit
git clone https://github.com/dangerzau/pihole-dns-sync.git
cd pihole-dns-sync
docker-compose build
docker-compose up
🚀 GitHub Actions
This repository includes a GitHub Actions workflow to automatically:

Build the Docker image

Push to GitHub Container Registry (GHCR) as ghcr.io/dangerzau/pihole-dns-sync:latest

You only need to git push, and everything else is handled automatically.

📜 License
MIT License

🎯 Notes
Works best with Pi-hole v6 (which introduced API support for DNS records)

Designed for homelab setups, media servers, internal apps, and self-hosted services

📣 Contributing
Pull requests and suggestions are welcome! Feel free to open an issue if you find a bug or want a feature added.


