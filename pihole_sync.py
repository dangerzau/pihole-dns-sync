import os
import json
import ipaddress
import docker
import requests
import time
import logging
import signal
import argparse
import threading
from typing import Optional, List, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Environment variables
PIHOLE_URL = os.getenv("PIHOLE_URL")
PIHOLE_PASSWORD = os.getenv("PIHOLE_PASSWORD")
DEFAULT_DNS_TARGET = os.getenv("DEFAULT_DNS_TARGET")
# names of containers to wait for before doing work; comma-separated
WAIT_FOR = [n.strip() for n in os.getenv("WAIT_FOR", "").split(",") if n.strip()]
# timeout (seconds) for wait loops, 0 means infinite
WAIT_TIMEOUT = int(os.getenv("WAIT_TIMEOUT_SECONDS", 0))

# Docker client
docker_client = docker.from_env()

# Constants for retry logic
MAX_RETRIES = int(os.getenv("MAX_RETRIES", 3))
RETRY_DELAY = int(os.getenv("RETRY_DELAY", 5))  # in seconds
# Debounce window for duplicate Docker events (seconds)
DEBOUNCE_SECONDS = float(os.getenv("DEBOUNCE_SECONDS", 0.5))
# Interval for periodic reconciliation (minutes). 0 disables automatic runs.
RECONCILE_INTERVAL = int(os.getenv("RECONCILE_INTERVAL_MINUTES", 0))
# If true the daemon will perform a full container scan immediately after
# startup (equivalent to running with `--scan`).  Useful if the service is
# started when other containers are already running.
SCAN_ON_START = os.getenv("SCAN_ON_START", "false").lower() in ("1", "true", "yes")

# Persistent state file to store processed records per container (id -> list of [name, target])
STATE_FILE = os.getenv("STATE_FILE", "pihole_state.json")


# -------------------------------------------------------------
# helper that waits for specified containers' health to become
# "healthy" using the Docker API.  The user can supply a list via
# the WAIT_FOR env var.
# -------------------------------------------------------------

def wait_for_healthy_containers(names: List[str], timeout: int = 0) -> bool:
    """Block until all given container names report a healthy status.

    If ``timeout`` is non‑zero the function will return False after that
    many seconds.  Otherwise it loops indefinitely.
    """
    if not names:
        return True

    logger.info(f"Waiting for containers to become healthy: {names} (timeout={timeout}s)")
    start = time.time()
    while True:
        all_ok = True
        for nm in names:
            try:
                cont = docker_client.containers.get(nm)
                health = cont.attrs.get("State", {}).get("Health", {}).get("Status")
                if health != "healthy":
                    all_ok = False
                    logger.debug(f"{nm} not healthy yet (status={health})")
                    break
            except docker.errors.NotFound:
                all_ok = False
                logger.debug(f"{nm} not found while waiting for health")
                break
            except Exception as e:
                all_ok = False
                logger.debug(f"error inspecting {nm}: {e}")
                break
        if all_ok:
            logger.info("All dependencies are healthy")
            return True
        if timeout and (time.time() - start) > timeout:
            logger.warning(f"Timeout waiting for healthy containers: {names}")
            return False
        time.sleep(2)

# Map of container_id -> list of (name, target) that we've successfully added
container_record_map = {}

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
current_session = {"sid": None, "obtained_at": None}
# recent_events stores timestamps of recent (container_id, status) events to debounce
recent_events = {}

# Session management constants
SESSION_TIMEOUT = int(os.getenv("SESSION_TIMEOUT", 1500))  # Default 25 minutes (Pi-hole v6 expires at 30 min, refresh with buffer)

# Global DNS mappings from environment variables (mapping1, mapping2, etc.)
global_dns_mappings: List[Tuple[str, str]] = []


def parse_mapping_env_vars() -> List[Tuple[str, str]]:
    """Parse environment variables matching pattern mapping1, mapping2, ... mapping99.
    
    Each variable should have format: mapping1=sourceaddress,destinationaddress
    For example: mapping1=abs.jimmyc.net,jf.jimmyc.net
    
    Returns a list of (sourceaddress, destinationaddress) tuples.
    If destinationaddress is an IP address, an A record will be created.
    Otherwise, a CNAME record will be created.
    """
    mappings = []
    for i in range(1, 100):
        mapping_key = f"mapping{i}"
        mapping_value = os.getenv(mapping_key)
        if mapping_value:
            try:
                parts = mapping_value.split(",")
                if len(parts) != 2:
                    logger.error(f"Invalid format for {mapping_key}='{mapping_value}'. Expected 'sourceaddress,destinationaddress'")
                    continue
                source = parts[0].strip()
                destination = parts[1].strip()
                if not source or not destination:
                    logger.error(f"Empty source or destination in {mapping_key}='{mapping_value}'")
                    continue
                mappings.append((source, destination))
                logger.info(f"Loaded global DNS mapping: {source} -> {destination}")
            except Exception as e:
                logger.error(f"Failed to parse {mapping_key}='{mapping_value}': {e}")
    return mappings


def get_session_id(force_refresh: bool = False) -> Optional[str]:
    """Authenticate with Pi-hole and retrieve the session ID."""
    global current_session
    
    # Check if we have a valid cached session
    if not force_refresh and current_session["sid"] is not None:
        elapsed = time.time() - current_session["obtained_at"]
        if elapsed < SESSION_TIMEOUT:
            logger.info(f"Using cached session ID (age: {elapsed:.0f}s)")
            return current_session["sid"]
        else:
            logger.info("Cached session expired. Re-authenticating...")
            # Logout the expired session before getting a new one
            logout_session(current_session["sid"])
            current_session["sid"] = None
    
    if force_refresh and current_session["sid"] is not None:
        logger.info(f"Force refreshing session. Logging out old session: {current_session['sid']}")
        logout_session(current_session["sid"])
        current_session["sid"] = None
    
    url = f"{PIHOLE_URL.rstrip('/')}/auth"
    payload = {"password": PIHOLE_PASSWORD}

    for attempt in range(MAX_RETRIES):
        try:
            logger.info("Authenticating with Pi-hole API to retrieve session ID...")
            response = requests.post(url, json=payload, verify=False)
            if response.status_code == 200:
                sid = response.json().get("session", {}).get("sid")
                if sid:
                    current_session["sid"] = sid
                    current_session["obtained_at"] = time.time()
                    logger.info(f"Successfully authenticated. New Session ID: {sid}")
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
    current_session["sid"] = None
    return None


def load_state() -> None:
    """Load persisted container->records mapping from STATE_FILE."""
    global container_record_map, processed_records
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r") as fh:
                data = json.load(fh)
            # Expecting dict of container_id -> list of [name, target]
            container_record_map = {}
            for cid, recs in data.items():
                container_record_map[cid] = [tuple(r) for r in recs]
            # Rebuild processed_records set
            processed_records = set()
            for recs in container_record_map.values():
                for rec in recs:
                    processed_records.add(tuple(rec))
            logger.info(f"Loaded state for {len(container_record_map)} containers from {STATE_FILE}")
        else:
            container_record_map = {}
    except Exception as e:
        logger.error(f"Failed to load state from {STATE_FILE}: {e}")


def save_state() -> None:
    """Persist container_record_map to STATE_FILE."""
    try:
        serializable = {cid: [[r[0], r[1]] for r in recs] for cid, recs in container_record_map.items()}
        with open(STATE_FILE, "w") as fh:
            json.dump(serializable, fh)
        logger.debug(f"Saved state for {len(container_record_map)} containers to {STATE_FILE}")
    except Exception as e:
        logger.error(f"Failed to save state to {STATE_FILE}: {e}")


def reconcile_state(session_id: str) -> None:
    """Ensure persisted records exist in Pi-hole. Attempts to add missing records."""
    if not session_id:
        logger.warning("No session ID; skipping reconciliation.")
        return
    try:
        total = 0
        fixed = 0
        logger.info(f"Reconciling persisted state from {STATE_FILE} ({len(container_record_map)} containers)...")
        for cid, recs in list(container_record_map.items()):
            for name, target in recs:
                total += 1
                try:
                    # add_record will treat existing records as success; it will also persist state
                    result = add_record(name, target, session_id, container_id=cid)
                    if result:
                        fixed += 1
                except Exception as e:
                    logger.error(f"Reconciliation: failed to ensure record {name}->{target} for container {cid}: {e}")
        logger.info(f"Reconciliation complete: ensured {fixed}/{total} persisted records exist in Pi-hole.")
    except Exception as e:
        logger.error(f"Reconciliation encountered an error: {e}")


def add_to_state(container_id: str, key: Tuple[str, str]) -> None:
    """Record that `key` (name,target) is associated with `container_id` and persist."""
    try:
        recs = container_record_map.setdefault(container_id, [])
        if tuple(key) not in recs:
            recs.append(tuple(key))
        processed_records.add(tuple(key))
        save_state()
    except Exception as e:
        logger.error(f"Failed to add to state for {container_id}: {e}")


def remove_container_state(container_id: str) -> None:
    """Remove persisted records associated with `container_id` and update processed_records."""
    try:
        recs = container_record_map.pop(container_id, [])
        for r in recs:
            try:
                processed_records.discard(tuple(r))
            except Exception:
                pass
        save_state()
    except Exception as e:
        logger.error(f"Failed to remove state for {container_id}: {e}")


def logout_session(session_id: str) -> bool:
    """Logout from Pi-hole API to clean up session."""
    if not session_id:
        return False
    
    url = f"{PIHOLE_URL.rstrip('/')}/auth"
    headers = {"X-FTL-SID": session_id}
    
    try:
        logger.info(f"[SESSION] Logging out session: {session_id}")
        response = requests.delete(url, headers=headers, timeout=10, verify=False)
        if response.status_code in [200, 204]:
            logger.info(f"[SESSION] Successfully logged out session: {session_id}")
            return True
        else:
            logger.warning(f"[SESSION] Logout returned unexpected status {response.status_code} for session: {session_id}")
            return False
    except requests.RequestException as e:
        logger.error(f"[SESSION] Exception during logout for session {session_id}: {e}")
        return False


def is_ip(address: str) -> bool:
    """Check if the given address is a valid IP."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def is_valid_hostname(hostname: str) -> bool:
    """Basic validation for hostnames (RFC-like checks)."""
    if not hostname or len(hostname) > 253:
        return False
    # Strip trailing dot for FQDNs
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    labels = hostname.split('.')
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False
        if not label[0].isalnum() or not label[-1].isalnum():
            return False
        for ch in label:
            if not (ch.isalnum() or ch == '-'):
                return False
    return True


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
            response = requests.request(method, endpoint, headers=headers, timeout=10, verify=False)
            if response.status_code in [200, 201, 204]:
                logger.info(f"{method.upper()} request to {endpoint} succeeded. Status: {response.status_code}")
                return response  # Exit the loop on success
            # If client error (other than 401/429), do not retry — likely bad request/parameters
            if 400 <= response.status_code < 500 and response.status_code not in (401, 429):
                # Try to detect Pi-hole uniqueness errors (item already present) and treat as success
                try:
                    raw = (response.text or "").lower()
                    if "already" in raw or "item already present" in raw:
                        logger.info(f"{method.upper()} request to {endpoint} returned 400 but indicates existing item; treating as success.")
                        # Mutate status_code to a success code so callers treat as success
                        response.status_code = 204
                        return response
                except Exception:
                    pass
                logger.error(f"{method.upper()} request to {endpoint} failed: {response.status_code}. Not retrying (client error). Body: {response.text}")
                return response
            elif response.status_code == 401:
                logger.error(f"Received 401 Unauthorized. Session may have expired. Attempting to re-authenticate...")
                new_sid = get_session_id(force_refresh=True)
                if new_sid:
                    # Update headers with new session ID and retry
                    headers["X-FTL-SID"] = new_sid
                    logger.info(f"[SESSION] Re-authenticated with new session. Retrying request...")
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY)
                        continue
                else:
                    logger.error("Failed to re-authenticate. Aborting request.")
                    return None
            elif response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", RETRY_DELAY))
                logger.warning(f"Rate limit exceeded. Retrying after {retry_after} seconds...")
                time.sleep(retry_after)
                continue
            else:
                # Only handle non-successful responses
                if attempt < MAX_RETRIES - 1:
                    backoff = RETRY_DELAY * (2 ** attempt)  # Exponential backoff for non-success responses
                    logger.warning(f"Request failed with status {response.status_code}. Retrying... (Attempt {attempt + 1} of {MAX_RETRIES}) after {backoff} seconds")
                    time.sleep(backoff)
                    continue
                else:
                    # Last attempt, log the error and break
                    handle_api_response(response, f"{method.upper()} request to {endpoint}")
                    break
        except requests.RequestException as e:
            logger.error(f"Exception during Pi-hole API call: {e}")
            if attempt < MAX_RETRIES - 1:
                backoff = RETRY_DELAY * (2 ** attempt)  # Exponential backoff
                logger.info(f"Retrying... (Attempt {attempt + 1} of {MAX_RETRIES}) after {backoff} seconds")
                time.sleep(backoff)
            else:
                logger.error(f"Failed to complete {method.upper()} request after {MAX_RETRIES} attempts.")
    return None


def handle_api_response(response: requests.Response, action: str) -> bool:
    """Handle API responses and log appropriate messages based on status codes."""
    if response.status_code in [200, 201, 204]:
        logger.info(f"{action} succeeded. Status: {response.status_code}")
        return True
    elif response.status_code == 400:
        # Try to extract a helpful message from the response body
        try:
            body = response.json()
            reason = body.get("message") or body.get("error") or body.get("detail") or json.dumps(body)
        except Exception:
            reason = response.text
        logger.error(f"{action} failed: Bad Request. {reason}. Status: {response.status_code}")
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





def add_record(name: str, target: str, session_id: str, container_id: Optional[str] = None, force: bool = False) -> bool:
    """Add a DNS record to Pi-hole. Returns True on success, False on failure.

    If ``force`` is True the function will attempt to add the record even if it
    has been seen previously.  This is useful for on‑demand scans where the
    caller wants to re‑push every known record to the API.
    """
    key = (name, target)
    if key in processed_records and not force:
        logger.info(f"Record {key} already processed, skipping.")
        return True  # Already processed successfully
    
    # Validate parameters locally to provide clearer error messages
    if not is_valid_hostname(name):
        logger.error(f"Bad parameters: invalid hostname for name: '{name}'")
        return False
    if not (is_ip(target) or is_valid_hostname(target)):
        logger.error(f"Bad parameters: invalid target '{target}' (must be IP or hostname)")
        return False

    endpoint = construct_endpoint(name, target, "add")
    headers = {"X-FTL-SID": session_id, "accept": "application/json"}
    response = send_request("put", endpoint, headers)

    if response and response.status_code in [200, 201, 204]:
        processed_records.add(key)
        logger.info(f"Successfully added DNS record: {name} -> {target}")
        return True
    # If the API returned a 400 with a body indicating the item already exists,
    # treat that as success (idempotent behavior) and do not retry. Be permissive
    # in parsing because Pi-hole may return different JSON shapes.
    if response and response.status_code == 400:
        try:
            body = None
            try:
                body = response.json()
            except Exception:
                body = None

            found_already = False
            # Check structured JSON first
            if isinstance(body, dict):
                # Top-level message
                for keyname in ("message", "detail"):
                    v = body.get(keyname)
                    if isinstance(v, str) and "already" in v.lower():
                        found_already = True
                        break
                # Nested error object
                if not found_already and "error" in body and isinstance(body["error"], dict):
                    for keyname in ("message", "detail"):
                        v = body["error"].get(keyname)
                        if isinstance(v, str) and "already" in v.lower():
                            found_already = True
                            break
            # Fallback: check raw text for common phrases (be permissive)
            try:
                raw = (response.text or "").lower()
            except Exception:
                raw = ""
            if not found_already and any(kw in raw for kw in ("item already present", "already present", "item already", "already")):
                found_already = True

            # Log the response body/text at INFO level when we didn't detect the condition
            if not found_already:
                try:
                    logger.info(f"add_record: 400 response.text={response.text}")
                    logger.info(f"add_record: parsed body={body}")
                except Exception:
                    pass

            if found_already:
                # Persist knowledge that this container has this record if container_id provided
                if container_id:
                    add_to_state(container_id, key)
                else:
                    processed_records.add(key)
                logger.info(f"Record already exists: {name} -> {target}. Treating as success.")
                return True
            # Final fallback: if we were trying to add a CNAME and got a 400, assume it's a uniqueness violation
            if not found_already and endpoint and ("cnameRecords" in endpoint or "dns%2FcnameRecords" in endpoint):
                logger.info(f"add_record: treating 400 on CNAME endpoint as already-present fallback for {name}->{target}")
                if container_id:
                    add_to_state(container_id, key)
                else:
                    processed_records.add(key)
                return True
        except Exception:
            # If parsing fails for any reason, fall through to the generic failure path
            pass
    else:
        logger.error(f"Failed to add DNS record ({name} -> {target}) after retries.")
        return False


def delete_record(name: str, target: str, session_id: str) -> bool:
    """Delete a DNS record from Pi-hole. Returns True on success, False on failure."""
    key = (name, target)
    endpoint = construct_endpoint(name, target, "delete")
    headers = {"X-FTL-SID": session_id, "accept": "application/json"}
    response = send_request("delete", endpoint, headers)
    # Treat 404 (not found) as success for idempotency — record already absent
    if response and response.status_code in [200, 201, 204, 404]:
        processed_records.discard(key)
        if response.status_code == 404:
            logger.info(f"Record not found (treated as deleted): {name} -> {target}")
        else:
            logger.info(f"Successfully deleted DNS record: {name} -> {target}")
        return True
    else:
        logger.error(f"Failed to delete DNS record ({name} -> {target}) after retries.")
        return False


def signal_handler(sig, frame):
    """Handle termination signals to gracefully stop event monitoring and logout."""
    global stop_event_monitoring, current_session
    logger.info("Termination signal received. Performing graceful shutdown...")
    stop_event_monitoring = True
    
    # Logout from Pi-hole if we have an active session
    if current_session["sid"]:
        logger.info(f"[SESSION] Closing active session on shutdown: {current_session['sid']}")
        logout_session(current_session["sid"])
        current_session["sid"] = None
    
    logger.info("Shutdown complete.")

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
                # Debounce duplicate events that arrive in quick succession
                try:
                    key = (cid, status)
                    now = time.time()
                    last = recent_events.get(key)
                    if last and (now - last) < DEBOUNCE_SECONDS:
                        logger.debug(f"Debounced duplicate event for {cid} status {status}")
                        continue
                    recent_events[key] = now
                except Exception:
                    pass
                try:
                    container = docker_client.containers.get(cid)
                    container_name = container.name  # Human-readable container name
                    records = parse_custom_records(container)
                    if records:
                        if status == "start":
                            logger.info(f"Processing DNS records for started container '{container_name}' (ID: {cid})...")
                            for name, target in records:
                                add_record(name, target, session_id, container_id=cid)
                        elif status == "stop":
                            logger.info(f"Removing DNS records for stopped container '{container_name}' (ID: {cid})...")
                            # Remove records discovered from labels
                            for name, target in records:
                                delete_record(name, target, session_id)
                            # Also attempt to remove any persisted records associated with this container
                            persisted = container_record_map.get(cid, [])
                            for name, target in persisted:
                                try:
                                    delete_record(name, target, session_id)
                                except Exception:
                                    pass
                            # Clear persisted state for this container
                            remove_container_state(cid)
                except docker.errors.NotFound:
                    logger.warning(f"Container with ID '{cid}' not found. Attempting to cleanup persisted records...")
                    # If the container can't be inspected, still try to remove persisted records
                    persisted = container_record_map.get(cid, [])
                    for name, target in persisted:
                        try:
                            delete_record(name, target, session_id)
                        except Exception:
                            pass
                    remove_container_state(cid)
                except Exception as e:
                    logger.error(f"Failed to process container '{container_name}' (ID: {cid}): {e}")
    except Exception as e:
        logger.error(f"Docker event monitoring encountered an error: {e}")


def scan_running_containers(session_id: str, force: bool = False) -> None:
    """Inspect every running container and ensure its DNS records exist.

    If ``force`` is true we re‑add records even if they were previously
    processed; the underlying ``add_record`` call will perform the API request
    regardless of cached state.
    """
    logger.info("Performing one‑time scan of all running containers for DNS labels...")
    try:
        for container in docker_client.containers.list():
            records = parse_custom_records(container)
            if records:
                for name, target in records:
                    add_record(name, target, session_id, container_id=container.id, force=force)
    except Exception as e:
        logger.error(f"Error during container scan: {e}")


def apply_global_dns_mappings(session_id: str, force: bool = False) -> None:
    """Apply global DNS mappings from environment variables to Pi-hole.
    
    These mappings are not tied to any specific container, so we use a synthetic
    container_id based on the mapping itself for state tracking purposes.
    """
    if not global_dns_mappings:
        return
    
    logger.info(f"Applying {len(global_dns_mappings)} global DNS mapping(s)...")
    try:
        for source, destination in global_dns_mappings:
            # Use a synthetic container_id for global mappings based on the source address
            synthetic_cid = f"global-mapping-{source}"
            add_record(source, destination, session_id, container_id=synthetic_cid, force=force)
    except Exception as e:
        logger.error(f"Error applying global DNS mappings: {e}")


def parse_args():
    parser = argparse.ArgumentParser(description="pihole-dns-sync utility")
    parser.add_argument(
        "--scan",
        action="store_true",
        help=(
            "Inspect all running containers and attempt to add DNS records for each. "
            "This operation always sends the API request even if the record was seen "
            "before, so it's useful for manual reconciliation from outside the daemon."
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="(currently ignored) kept for backwards compatibility",
    )
    return parser.parse_args()


def periodic_reconcile_thread(session_id: str) -> None:
    """Background thread that performs reconciliation at configured intervals."""
    logger.info(f"Periodic reconciliation thread started (interval={RECONCILE_INTERVAL}m)")
    while not stop_event_monitoring:
        # sleep in small chunks so we can respond quickly to shutdown signal
        remaining = RECONCILE_INTERVAL * 60
        while remaining > 0 and not stop_event_monitoring:
            time.sleep(min(remaining, 5))
            remaining -= 5
        if stop_event_monitoring:
            break
        if RECONCILE_INTERVAL > 0:
            try:
                logger.info("Periodic reconciliation triggered")
                reconcile_state(session_id)
                # Also re-apply global mappings during periodic reconciliation
                apply_global_dns_mappings(session_id)
            except Exception as e:
                logger.error(f"Periodic reconcile error: {e}")
    logger.info("Periodic reconciliation thread exiting")


def main() -> None:
    global current_session, global_dns_mappings
    args = parse_args()

    try:
        logger.info("Starting pihole-dns-sync...")
        
        # Parse global DNS mappings from environment variables
        global_dns_mappings = parse_mapping_env_vars()
        
        # optionally wait for other services (traefik, pihole, etc.)
        if WAIT_FOR:
            wait_for_healthy_containers(WAIT_FOR, timeout=WAIT_TIMEOUT)
        # Load persisted state and authenticate
        load_state()
        session_id = get_session_id()
        if not session_id:
            logger.error("Unable to retrieve session ID. Exiting...")
            return

        # If we're invoked in scan mode just perform the audit and exit
        if args.scan:
            # first make sure any previously‑persisted records exist in Pi-hole
            reconcile_state(session_id)
            # scan mode always re‑pushes records to the API so that an external
            # caller can be confident Pi-hole is up to date
            scan_running_containers(session_id, force=True)
            apply_global_dns_mappings(session_id, force=True)
            return

        # Otherwise behave as the normal long‑running daemon
        # Reconcile persisted records into Pi-hole initially
        reconcile_state(session_id)

        # perform an initial scan if requested via environment
        if SCAN_ON_START:
            logger.info("SCAN_ON_START enabled; performing initial container scan")
            scan_running_containers(session_id, force=True)
        
        # Apply global DNS mappings at startup
        apply_global_dns_mappings(session_id, force=True)

        # start periodic reconciliation thread if interval configured
        if RECONCILE_INTERVAL > 0:
            t = threading.Thread(target=periodic_reconcile_thread, args=(session_id,), daemon=True)
            t.start()

        monitor_events(session_id)
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt.")
    finally:
        # Ensure we logout on exit
        if current_session["sid"]:
            logger.info(f"[SESSION] Cleaning up session on exit: {current_session['sid']}")
            logout_session(current_session["sid"])
            current_session["sid"] = None
        logger.info("pihole-dns-sync stopped.")


if __name__ == "__main__":
    main()
