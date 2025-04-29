#!/bin/bash

set -e

echo "🔨 Building Docker image locally..."
docker compose build

echo "🐳 Starting pihole-dns-sync container..."
docker compose up
