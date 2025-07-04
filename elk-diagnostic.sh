#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== ELK Stack Diagnostic Tool ===${NC}"

echo -e "${BLUE}=== System Information ===${NC}"
echo "Available Memory:"
free -h
echo ""

echo "vm.max_map_count setting:"
cat /proc/sys/vm/max_map_count
echo ""

echo "Docker Swarm Nodes:"
docker node ls
echo ""

echo -e "${BLUE}=== Service Status ===${NC}"
echo "ELK Services:"
docker service ls --filter name=elk_
echo ""

echo -e "${BLUE}=== Service Details ===${NC}"
for service in elk_elasticsearch1 elk_elasticsearch2 elk_elasticsearch3 elk_kibana; do
    echo -e "${YELLOW}--- $service ---${NC}"
    echo "Status:"
    docker service ps $service --no-trunc --format "table {{.ID}}\t{{.Name}}\t{{.Node}}\t{{.DesiredState}}\t{{.CurrentState}}\t{{.Error}}" 2>/dev/null || echo "Service not found"
    echo ""
done

echo -e "${BLUE}=== Docker System Information ===${NC}"
echo "Docker System Usage:"
docker system df
echo ""

echo "Docker Info (Swarm section):"
docker info | grep -A 10 "Swarm:"
echo ""

echo -e "${BLUE}=== Configuration Files ===${NC}"
echo "Checking if key files exist:"
files_to_check=(
    "./docker-stack.yml"
    "./.env"
    "./tls/certs/ca/ca.crt"
    "./setup/entrypoint.sh"
)

for file in "${files_to_check[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✓ $file exists${NC}"
    else
        echo -e "${RED}✗ $file missing${NC}"
    fi
done
echo ""

echo -e "${BLUE}=== Environment Variables ===${NC}"
if [ -f .env ]; then
    echo "Key environment variables (values hidden for security):"
    grep -E "(ELASTIC_PASSWORD|KIBANA_SYSTEM_PASSWORD|ELASTIC_VERSION)" .env 
#| sed 's/=.*$/=***/'
else
    echo -e "${RED}.env file not found${NC}"
fi
echo ""

echo -e "${BLUE}=== Recent Service Logs ===${NC}"
for service in elk_elasticsearch1 elk_elasticsearch2 elk_elasticsearch3 elk_kibana; do
    echo -e "${YELLOW}--- $service logs (last 20 lines) ---${NC}"
    docker service logs $service --tail 20 2>/dev/null || echo "No logs available for $service"
    echo ""
done
