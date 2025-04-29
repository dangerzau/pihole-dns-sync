
import os
import re
import time
import requests
import logging
from docker import from_env
from prometheus_client import start_http_server, Counter
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# Prometheus metrics
metrics = {
    "adds": Counter("pihole_dns_adds", "Number of DNS records added"),
    "removes": Counter("pihole_dns_removes", "Number of DNS records removed"),
    "errors": Counter("pihole_dns_errors", "Number of errors during DNS operation"),
}

# Configurable environment variables
PIHOLE_URL = os.getenv("PIHOLE_URL", "").strip()
TRAEFIK_WATCH = os.getenv("TRAEFIK_WATCH", "true").lower() == "true"
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
TARGET = os.getenv("TARGET", "")
HEALTHCHECK_PORT = os.getenv("HEALTHCHECK_PORT", "8000")

# Set Pi-hole URL if just IP provided
if not PIHOLE_URL:
    log.critical("PIHOLE_URL environment variable is required.")
    exit(1)

parsed = urlparse(PIHOLE_URL)
if not parsed.scheme:
    # Assume it's just an IP, build full URL
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", PIHOLE_URL):
        PIHOLE_URL = f"http://{PIHOLE_URL}"
        log.info(f"Inferred PIHOLE_URL as {PIHOLE_URL}")
    else:
        log.critical("Invalid PIHOLE_URL format. Must be full URL or valid IP.")
        exit(1)

# Initialize Docker client
client = from_env()

# Active container hostnames to avoid duplicates
active_hostnames = set()

# Docker event listener function
def listen_for_docker_events():
    log.info("Starting to listen for Docker events...")
    for event in client.events(decode=True):
        if event["Type"] == "container":
            container = client.containers.get(event["id"])
            status = event["status"]

            if status in ["start", "die"]:
                process_container(container, status)

# Function to extract hostnames from Traefik labels
def extract_hosts_from_labels(labels):
    rule = labels.get("traefik.http.routers.default.rule", "")
    hostnames = re.findall(r"Host\(`(.*?)`\)", rule)
    return hostnames

# Function to extract hostnames in manual mode (from environment variables)
def extract_host_manual_mode(container):
    env_vars = container.attrs.get("Config", {}).get("Env", [])
    env_dict = dict(var.split("=", 1) for var in env_vars if "=" in var)
    container_host = env_dict.get("CONTAINER_HOST")
    target_host = env_dict.get("TARGET_HOST")

    if container_host and target_host:
        return [(container_host, target_host)]
    return []

# Main container processing logic
def process_container(container, status):
    entries = []

    if TRAEFIK_WATCH:
        labels = container.attrs.get("Config", {}).get("Labels", {})
        hostnames = extract_hosts_from_labels(labels)
        entries = [(hostname, TARGET) for hostname in hostnames]
    else:
        entries = extract_host_manual_mode(container)

    for hostname, destination in entries:
        is_ip = re.match(r"^(\d{1,3}\.){3}\d{1,3}$", destination or "")
        if status == "start" and hostname not in active_hostnames:
            create_record_type(hostname, destination, is_ip)
            active_hostnames.add(hostname)
        elif status == "die" and hostname in active_hostnames:
            delete_record_type(hostname, is_ip)
            active_hostnames.remove(hostname)

# Function to create the appropriate DNS record (A or CNAME)
def create_record_type(hostname, destination, is_ip):
    if DRY_RUN:
        log.info(f"[DRY-RUN] Would create DNS record: {hostname} -> {destination}")
        return
    try:
        url = f"{PIHOLE_URL}/api/v1/dns/records/" + ("a" if is_ip else "cname")
        payload = { "name": hostname, "ip" if is_ip else "target": destination }
        r = requests.post(url, headers={"Authorization": f"Bearer {os.getenv('PIHOLE_TOKEN')}"}, json=payload)
        r.raise_for_status()
        metrics["adds"].inc()
        log.info(f"Added DNS record: {hostname} -> {destination}")
    except Exception as e:
        metrics["errors"].inc()
        raise e

# Function to delete the appropriate DNS record (A or CNAME)
def delete_record_type(hostname, is_ip):
    if DRY_RUN:
        log.info(f"[DRY-RUN] Would delete DNS record: {hostname}")
        return
    try:
        url = f"{PIHOLE_URL}/api/v1/dns/records/" + ("a" if is_ip else "cname") + f"/{hostname}"
        r = requests.delete(url, headers={"Authorization": f"Bearer {os.getenv('PIHOLE_TOKEN')}"})
        if r.status_code != 204:
            log.warning(f"Failed to delete DNS record for {hostname} (status {r.status_code})")
        else:
            log.info(f"Deleted DNS record for {hostname}")
        metrics["removes"].inc()
    except Exception as e:
        metrics["errors"].inc()
        raise e

# Healthcheck endpoint (Prometheus or other monitoring systems)
def start_healthcheck_server():
    start_http_server(int(HEALTHCHECK_PORT))
    log.info(f"Healthcheck server started on port {HEALTHCHECK_PORT}")

if __name__ == "__main__":
    start_healthcheck_server()
    listen_for_docker_events()
