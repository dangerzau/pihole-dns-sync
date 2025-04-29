import os
import docker
import requests
import time
from prometheus_client import start_http_server, Counter
from flask import Flask
from flask_healthcheck import HealthCheck

# Environment Variables
PIHOLE_URL = os.getenv('PIHOLE_URL', 'http://192.168.1.10')
PIHOLE_TOKEN = os.getenv('PIHOLE_TOKEN')
TRAEFIK_WATCH = os.getenv('TRAEFIK_WATCH', 'true').lower() == 'true'
TARGET = os.getenv('TARGET')
DRY_RUN = os.getenv('DRY_RUN', 'false').lower() == 'true'
HEALTHCHECK_PORT = int(os.getenv('HEALTHCHECK_PORT', 8000))

# Docker client
client = docker.from_env()

# Prometheus metrics
record_created = Counter('pihole_dns_record_created', 'Total records created')
record_deleted = Counter('pihole_dns_record_deleted', 'Total records deleted')

# Flask app for healthcheck
app = Flask(__name__)
health = HealthCheck()

def get_pihole_api_url():
    # Ensure PIHOLE_URL is either a full URL or IP address
    if PIHOLE_URL.startswith('http'):
        return PIHOLE_URL
    return f'http://{PIHOLE_URL}/admin/api.php'

def pihole_api_call(url, params):
    headers = {
        'Authorization': f'Bearer {PIHOLE_TOKEN}'
    }
    response = requests.get(url, params=params, headers=headers)
    response.raise_for_status()
    return response.json()

def create_record(hostname, target):
    url = get_pihole_api_url()
    record_type = 'A' if target.count('.') == 3 else 'CNAME'
    params = {
        'host': hostname,
        'type': record_type,
        'content': target,
        'token': PIHOLE_TOKEN
    }
    if DRY_RUN:
        print(f"DRY-RUN: Would create {record_type} record for {hostname} pointing to {target}")
        return
    try:
        result = pihole_api_call(url, params)
        if result.get('status') == 'ok':
            record_created.inc()
            print(f"Created {record_type} record: {hostname} -> {target}")
        else:
            print(f"Failed to create {record_type} record for {hostname}")
    except requests.exceptions.RequestException as e:
        print(f"Error creating record: {e}")

def delete_record(hostname):
    url = get_pihole_api_url()
    params = {
        'host': hostname,
        'token': PIHOLE_TOKEN
    }
    if DRY_RUN:
        print(f"DRY-RUN: Would delete record for {hostname}")
        return
    try:
        result = pihole_api_call(url, params)
        if result.get('status') == 'ok':
            record_deleted.inc()
            print(f"Deleted record for {hostname}")
        else:
            print(f"Failed to delete record for {hostname}")
    except requests.exceptions.RequestException as e:
        print(f"Error deleting record: {e}")

def handle_container_event(event):
    container = event['actor']['Attributes']
    container_name = container.get('name')
    if container_name is None:
        return

    print(f"Handling event for container: {container_name} - {event['Action']}")

    if TRAEFIK_WATCH:
        traefik_host = container.get('traefik.http.routers.myrouter.rule', None)
        if traefik_host:
            hostname = traefik_host.split('Host(')[-1].split(')')[0]
            target = TARGET if TARGET else container.get('IP')
            if event['Action'] == 'start':
                create_record(hostname, target)
            elif event['Action'] == 'stop':
                delete_record(hostname)
    else:
        container_host = container.get('CONTAINER_HOST')
        target_host = container.get('TARGET_HOST')
        if container_host and target_host:
            if event['Action'] == 'start':
                create_record(container_host, target_host)
            elif event['Action'] == 'stop':
                delete_record(container_host)

def container_event_listener():
    for event in client.events(decode=True):
        handle_container_event(event)

@app.route("/health", methods=["GET"])
def healthcheck():
    return "OK", 200

if __name__ == "__main__":
    start_http_server(HEALTHCHECK_PORT)
    app.run(host='0.0.0.0', port=HEALTHCHECK_PORT, debug=False)
    container_event_listener()
