import os
import json
import ipaddress
import docker
import requests

# Environment variables
PIHOLE_URL = os.getenv("PIHOLE_URL")
PIHOLE_PASSWORD = os.getenv("PIHOLE_PASSWORD")
DEFAULT_DNS_TARGET = os.getenv("DEFAULT_DNS_TARGET")

# Docker client
docker_client = docker.from_env()

def get_session_id():
    """Authenticate with Pi-hole and retrieve the session ID."""
    url = f"{PIHOLE_URL}/auth"
    payload = {"password": PIHOLE_PASSWORD}
    try:
        print("[INFO] Authenticating with Pi-hole API to retrieve session ID...")
        response = requests.post(url, json=payload, verify=False)
        if response.status_code == 200:
            data = response.json()
            sid = data["session"]["sid"]
            print(f"[INFO] Successfully authenticated. Session ID: {sid}")
            return sid
        else:
            print(f"[ERROR] Failed to authenticate. Status: {response.status_code}, Body: {response.text}")
            return None
    except Exception as e:
        print(f"[ERROR] Exception during authentication: {e}")
        return None

def is_ip(address):
    """Check if the given address is a valid IP."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def parse_custom_records(container):
    """Parse DNS records from container labels or fallback to default logic."""
    labels = container.labels or {}
    records = []

    # Check for pihole.custom-record label
    if "pihole.custom-record" in labels:
        print(f"[DEBUG] Found pihole.custom-record: {labels['pihole.custom-record']}")
        try:
            entries = json.loads(labels["pihole.custom-record"].replace("'", '"'))
            for pair in entries:
                if len(pair) == 2:
                    records.append((pair[0], pair[1]))
            print(f"[DEBUG] Parsed Records: {records}")
        except Exception as e:
            print(f"[ERROR] Failed to parse pihole.custom-record for container {container.name}: {e}")
    else:
        # Fall back to extracting source from Traefik host rules
        default_target = DEFAULT_DNS_TARGET
        if not default_target:
            print("[ERROR] DEFAULT_DNS_TARGET environment variable is not set. Skipping container.")
            return None
        
        for key, value in labels.items():
            if key.startswith("traefik.http.routers.") and ".rule" in key and "Host(`" in value:
                # Extract hostname from Traefik rule: Host(`example.com`) -> example.com
                source = value.split("Host(`")[1].split("`)")[0]
                records.append((source, default_target))
                print(f"[INFO] Using Traefik host rule: {source} -> {default_target}")
    return records if records else None

def add_record(name, target, session_id):
    """Add a DNS record to Pi-hole."""
    endpoint = f"{PIHOLE_URL}/config/dns%2Fhosts/{target}%20{name}" if is_ip(target) else f"{PIHOLE_URL}/config/dns%2FcnameRecords/{name}%2C{target}"
    headers = {
        "X-FTL-SID": session_id,
        "accept": "application/json"
    }
    try:
        print(f"[INFO] Sending request to Pi-hole to add DNS record ({name} -> {target})")
        res = requests.put(endpoint, headers=headers)
        print(f"[DEBUG] Pi-hole Response: Status={res.status_code}, Body={res.text}")
        if res.status_code == 200:
            print(f"[INFO] Pi-hole API: DNS record added successfully ({name} -> {target})")
        elif res.status_code == 409:
            print(f"[INFO] Pi-hole API: DNS record already exists ({name} -> {target})")
        else:
            print(f"[ERROR] Pi-hole API: Failed to add DNS record ({name} -> {target}): {res.status_code} {res.text}")
    except Exception as e:
        print(f"[ERROR] Exception during Pi-hole API call for DNS record ({name} -> {target}): {e}")

def delete_record(name, target, session_id):
    """Delete a DNS record from Pi-hole."""
    endpoint = f"{PIHOLE_URL}/config/dns%2Fhosts/{target}%20{name}" if is_ip(target) else f"{PIHOLE_URL}/config/dns%2FcnameRecords/{name}%2C{target}"
    headers = {
        "X-FTL-SID": session_id,
        "accept": "application/json"
    }
    try:
        print(f"[INFO] Sending request to Pi-hole to delete DNS record ({name} -> {target})")
        res = requests.delete(endpoint, headers=headers)
        print(f"[DEBUG] Pi-hole Response: Status={res.status_code}, Body={res.text}")
        if res.status_code == 204:
            print(f"[INFO] Pi-hole API: DNS record deleted successfully ({name} -> {target})")
        elif res.status_code == 404:
            print(f"[INFO] Pi-hole API: DNS record not found ({name} -> {target}). Nothing to delete.")
        else:
            print(f"[ERROR] Pi-hole API: Failed to delete DNS record ({name} -> {target}): {res.status_code} {res.text}")
    except Exception as e:
        print(f"[ERROR] Exception during Pi-hole API call to delete DNS record ({name} -> {target}): {e}")

def monitor_events(session_id):
    """Monitor Docker events and process containers with or without 'pihole.custom-record'."""
    print("[INFO] Monitoring Docker events for containers with piholeup=yes label...")
    try:
        for event in docker_client.events(decode=True):
            if event.get("Type") == "container" and event.get("status") == "start":
                cid = event.get("id")
                try:
                    container = docker_client.containers.get(cid)
                    records = parse_custom_records(container)
                    if records:
                        print(f"[INFO] Found piholeup=yes label on container {cid}. Processing DNS records...")
                        for name, target in records:
                            add_record(name, target, session_id)
                except docker.errors.NotFound:
                    continue
                except Exception as e:
                    print(f"[ERROR] Failed to process container {cid}: {e}")
            elif event.get("Type") == "container" and event.get("status") == "stop":
                cid = event.get("id")
                try:
                    container = docker_client.containers.get(cid)
                    records = parse_custom_records(container)
                    if records:
                        print(f"[INFO] Found piholeup=yes label on stopped container {cid}. Removing DNS records...")
                        for name, target in records:
                            delete_record(name, target, session_id)
                except docker.errors.NotFound:
                    continue
                except Exception as e:
                    print(f"[ERROR] Failed to process stopped container {cid}: {e}")
    except Exception as e:
        print(f"[ERROR] Docker event monitoring encountered an error: {e}")

def main():
    print("[INFO] Starting pihole-dns-sync...")
    session_id = get_session_id()
    if not session_id:
        print("[ERROR] Unable to retrieve session ID. Exiting...")
        return
    monitor_events(session_id)

if __name__ == "__main__":
    main()