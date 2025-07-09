#!/bin/bash

set -e

echo "=== Testing Microservice A (Ingress: esigo.dev) ==="
curl -i -H "Host: esigo.dev" http://localhost:8090/

echo -e "\n"

echo "=== Testing Microservice B (Ingress: microappb.esigo.dev) ==="
curl -i -H "Host: microappb.esigo.dev" http://localhost:8090/hello -d '{"s":"world"}' -H "Content-Type: application/json"

echo -e "\n=== Test Completed ==="
