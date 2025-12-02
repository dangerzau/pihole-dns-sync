import os
import json
import ipaddress
import docker
import requests
import time
import logging
import signal
from typing import Optional, List, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Environment variables
PIHOLE_URL = os.getenv("PIHOLE_URL")
PIHOLE_PASSWORD = os.getenv("PIHOLE_PASSWORD")
DEFAULT_DNS_TARGET = os.getenv("DEFAULT_DNS_TARGET")

# Docker client
docker_client = docker.from_env()

# Constants for retry logic
MAX_RETRIES = int(os.getenv("MAX_RETRIES", 3))
RETRY_DELAY = int(os.getenv("RETRY_DELAY", 5))  # in seconds

# Global flag to control event monitoring
stop_event_monitoring = False

# Validate environment variables
if not PIHOLE_URL or not PIHOLE_PASSWORD:
    logger.error("PIHOLE_URL and PIHOLE_PASSWORD environment variables must be set.")
    exit(1)

if not DEFAULT_DNS_TARGET:
    logger.warning("DEFAULT_DNS_TARGET environment variable is not set. Some containers may be skipped.")

# At the top of your file
processed_records = set()

def get_session_id() -> Optional[str]:
    """Authenticate with Pi-hole and retrieve the session ID."""
    url = f"{PIHOLE_URL.rstrip('/')}/auth"
    payload = {"password": PIHOLE_PASSWORD}

    for attempt in range(MAX_RETRIES):
        try:
            logger.info("Authenticating with Pi-hole API to retrieve session ID...")
            response = requests.post(url, json=payload, verify=False)
            if response.status_code == 200:
                sid = response.json().get("session", {}).get("sid")
                if sid:
                    logger.info(f"Successfully authenticated. Session ID: {sid}")
                    return sid
            elif response.status_code == 401:
                logger.error("Authentication failed: Unauthorized. Check Pi-hole password.")
                return None
            else:
                handle_api_response(response, "Authentication")
        except requests.RequestException as e:
            logger.error(f"Exception during authentication: {e}")
            if attempt < MAX_RETRIES - 1:
                logger.info(f"Retrying authentication... (Attempt {attempt + 1} of {MAX_RETRIES})")
                time.sleep(RETRY_DELAY)
    logger.error("Authentication failed after multiple attempts.")
    return None


def is_ip(address: str) -> bool:
    """Check if the given address is a valid IP."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def parse_custom_records(container) -> Optional[List[Tuple[str, str]]]:
    """Parse DNS records from container labels or fallback to default logic."""
    labels = container.labels or {}
    records = []

    if "pihole.custom-record" in labels:
        logger.debug(f"Found pihole.custom-record: {labels['pihole.custom-record']}")
        try:
            entries = json.loads(labels["pihole.custom-record"].replace("'", '"'))
            records = [(pair[0], pair[1]) for pair in entries if len(pair) == 2]
            logger.debug(f"Parsed Records: {records}")
        except Exception as e:
            logger.error(f"Failed to parse pihole.custom-record for container {container.name}: {e}")
    else:
        if not DEFAULT_DNS_TARGET:
            logger.error("DEFAULT_DNS_TARGET environment variable is not set. Skipping container.")
            return None

        for key, value in labels.items():
            if key.startswith("traefik.http.routers.") and ".rule" in key and "Host(`" in value:
                source = value.split("Host(`")[1].split("`)")[0]
                records.append((source, DEFAULT_DNS_TARGET))
                logger.info(f"Using Traefik host rule: {source} -> {DEFAULT_DNS_TARGET}")

    # After collecting records
    # Remove duplicates
    records = list(set(records))
    return records if records else None


def send_request(method: str, endpoint: str, headers: dict) -> Optional[requests.Response]:
    """Send a request to the Pi-hole API with retry logic and handle responses."""
    for attempt in range(MAX_RETRIES):
        try:
            logger.info(f"Sending {method.upper()} request to Pi-hole: {endpoint}")
            response = requests.request(method, endpoint, headers=headers)
            if response.status_code in [200, 201, 204]:
                logger.info(f"{method.upper()} request to {endpoint} succeeded. Status: {response.status_code}")
                return response  # Exit the loop on success
            elif response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", RETRY_DELAY))
                logger.warning(f"Rate limit exceeded. Retrying after {retry_after} seconds...")
                time.sleep(retry_after)
                continue
            else:
                # Only handle non-successful responses
                handle_api_response(response, f"{method.upper()} request to {endpoint}")
        except requests.RequestException as e:
            logger.error(f"Exception during Pi-hole API call: {e}")
            backoff = RETRY_DELAY * (2 ** attempt)  # Exponential backoff
            if attempt < MAX_RETRIES - 1:
                logger.info(f"Retrying... (Attempt {attempt + 1} of {MAX_RETRIES}) after {backoff} seconds")
                time.sleep(backoff)
    logger.error(f"Failed to complete {method.upper()} request after {MAX_RETRIES} attempts.")
    return None


def handle_api_response(response: requests.Response, action: str) -> bool:
    """Handle API responses and log appropriate messages based on status codes."""
    if response.status_code in [200, 201, 204]:
        logger.info(f"{action} succeeded. Status: {response.status_code}")
        return True
    elif response.status_code == 400:
        logger.error(f"{action} failed: Bad Request. Check parameters. Status: {response.status_code}")
    elif response.status_code == 401:
        logger.error(f"{action} failed: Unauthorized. Missing or invalid session ID. Status: {response.status_code}")
    elif response.status_code == 403:
        logger.error(f"{action} failed: Forbidden. API key lacks permissions. Status: {response.status_code}")
    elif response.status_code == 404:
        logger.error(f"{action} failed: Not Found. Resource does not exist. Status: {response.status_code}")
    elif response.status_code == 429:
        logger.error(f"{action} failed: Too Many Requests. Rate limit exceeded. Status: {response.status_code}")
    elif response.status_code >= 500:
        logger.error(f"{action} failed: Server error on Pi-hole's end. Status: {response.status_code}")
    else:
        logger.error(f"{action} failed: Unexpected error. Status: {response.status_code}, Body: {response.text}")
    return False


def construct_endpoint(name: str, target: str, action: str) -> str:
    if action == "add" or action == "delete":
        if is_ip(target):
            return f"{PIHOLE_URL}config/dns/hosts/{target} {name}"
        else:
            return f"{PIHOLE_URL}config/dns%2FcnameRecords/{name}%2C{target}"
    raise ValueError(f"Invalid action '{action}' specified for endpoint construction.")


def add_record(name: str, target: str, session_id: str) -> None:
    key = (name, target)
    if key in processed_records:
        logger.info(f"Record {key} already processed, skipping.")
        return
    endpoint = construct_endpoint(name, target, "add")
    headers = {"X-FTL-SID": session_id, "accept": "application/json"}
    response = send_request("put", endpoint, headers)
    if response:
        processed_records.add(key)
    else:
        logger.error(f"Failed to add DNS record ({name} -> {target}) after retries.")


def delete_record(name: str, target: str, session_id: str) -> None:
    """Delete a DNS record from Pi-hole."""
    key = (name, target)
    endpoint = construct_endpoint(name, target, "delete")
    headers = {"X-FTL-SID": session_id, "accept": "application/json"}
    response = send_request("delete", endpoint, headers)
    if response:
        # Remove from processed_records so it can be re-added later
        processed_records.discard(key)
    else:
        logger.error(f"Failed to delete DNS record ({name} -> {target}) after retries.")


def signal_handler(sig, frame):
    """Handle termination signals to gracefully stop event monitoring."""
    global stop_event_monitoring
    logger.info("Termination signal received. Stopping event monitoring...")
    stop_event_monitoring = True

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def monitor_events(session_id: str) -> None:
    """Monitor Docker events and process containers with or without 'pihole.custom-record'."""
    global stop_event_monitoring
    logger.info("Monitoring Docker events for containers with piholeup=yes label...")
    try:
        event_filters = {"event": ["start", "stop"]}
        for event in docker_client.events(decode=True, filters=event_filters):
            if stop_event_monitoring:
                logger.info("Stopping Docker event monitoring...")
                break
            if event.get("Type") == "container":
                cid = event.get("id")
                status = event.get("status")
                try:
                    container = docker_client.containers.get(cid)
                    container_name = container.name  # Human-readable container name
                    records = parse_custom_records(container)
                    if records:
                        if status == "start":
                            logger.info(f"Processing DNS records for started container '{container_name}' (ID: {cid})...")
                            for name, target in records:
                                add_record(name, target, session_id)
                        elif status == "stop":
                            logger.info(f"Removing DNS records for stopped container '{container_name}' (ID: {cid})...")
                            for name, target in records:
                                delete_record(name, target, session_id)
                except docker.errors.NotFound:
                    logger.warning(f"Container with ID '{cid}' not found. Skipping...")
                except Exception as e:
                    logger.error(f"Failed to process container '{container_name}' (ID: {cid}): {e}")
    except Exception as e:
        logger.error(f"Docker event monitoring encountered an error: {e}")


def main() -> None:
    logger.info("Starting pihole-dns-sync...")
    session_id = get_session_id()
    if not session_id:
        logger.error("Unable to retrieve session ID. Exiting...")
        return
    monitor_events(session_id)


if __name__ == "__main__":
    main()
