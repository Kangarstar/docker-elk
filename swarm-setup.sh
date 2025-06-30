#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== ELK Stack Swarm Setup ===${NC}"

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '#' | awk '/=/ {print $1}')
    echo -e "${GREEN}✓ Loaded environment variables${NC}"
else
    echo -e "${RED}✗ .env file not found${NC}"
    exit 1
fi

# Check if TLS certificates exist
if [ ! -f "./tls/certs/ca/ca.crt" ]; then
    echo -e "${YELLOW}⚠ TLS certificates not found. Running TLS setup...${NC}"
    docker compose up tls -d
    sleep 5
    echo -e "${GREEN}✓ TLS certificates generated${NC}"
else
    echo -e "${GREEN}✓ TLS certificates found${NC}"
fi



# Create Docker secrets from TLS certificates
echo -e "${YELLOW}Updating Docker secrets for TLS certificates...${NC}"

# Remove existing secrets if they exist (ignore errors)
docker secret rm elk_ca_crt 2>/dev/null || true
docker secret rm elk_elasticsearch_crt 2>/dev/null || true
docker secret rm elk_elasticsearch_key 2>/dev/null || true
docker secret rm elk_kibana_crt 2>/dev/null || true
docker secret rm elk_kibana_key 2>/dev/null || true

# Create new secrets
docker secret create elk_ca_crt ./tls/certs/ca/ca.crt
docker secret create elk_elasticsearch_crt ./tls/certs/elasticsearch/elasticsearch.crt
docker secret create elk_elasticsearch_key ./tls/certs/elasticsearch/elasticsearch.key
docker secret create elk_kibana_crt ./tls/certs/kibana/kibana.crt
docker secret create elk_kibana_key ./tls/certs/kibana/kibana.key

echo -e "${GREEN}✓ Docker secrets updated${NC}"

# Create overlay network if it doesn't exist
if ! docker network inspect elk >/dev/null 2>&1; then
    echo -e "${YELLOW}Creating overlay network 'elk'...${NC}"
    docker network create --driver overlay --attachable elk
    echo -e "${GREEN}✓ Network 'elk' created${NC}"
else
    echo -e "${GREEN}✓ Network 'elk' already exists${NC}"
fi

# Label nodes for Elasticsearch placement (optional - for node affinity)
echo -e "${YELLOW}Setting up node labels for Elasticsearch placement...${NC}"
NODES=($(docker node ls --format "{{.Hostname}}" | head -3))

if [ ${#NODES[@]} -ge 3 ]; then
    docker node update --label-add elasticsearch1=true ${NODES[0]} || true
    docker node update --label-add elasticsearch2=true ${NODES[1]} || true
    docker node update --label-add elasticsearch3=true ${NODES[2]} || true
    echo -e "${GREEN}✓ Node labels set${NC}"
else
    echo -e "${YELLOW}⚠ Less than 3 nodes available. Elasticsearch nodes may be placed on same nodes.${NC}"
fi

# Deploy the stack
echo -e "${YELLOW}Deploying ELK stack...${NC}"
docker stack deploy -d -c docker-stack.yml elk

# Wait longer for Elasticsearch cluster to be ready
echo -e "${YELLOW}Waiting for Elasticsearch cluster to be ready...${NC}"
echo -e "${BLUE}This may take several minutes for a 3-node cluster...${NC}"
sleep 60  # Increased from 30 seconds

# Enhanced readiness check with better error reporting
MAX_RETRIES=60  # Increased from 30
RETRY_COUNT=0
ES_READY=false

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    echo -e "${YELLOW}Checking Elasticsearch readiness... (${RETRY_COUNT}/${MAX_RETRIES})${NC}"

  # Check if Elasticsearch is responding
    if curl -s --connect-timeout 5 --max-time 10 --cacert ./tls/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" "https://localhost:9200/_cluster/health" > /tmp/es_health.json 2>/dev/null; then
        CLUSTER_STATUS=$(cat /tmp/es_health.json | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        ACTIVE_NODES=$(cat /tmp/es_health.json | grep -o '"number_of_nodes":[0-9]*' | cut -d':' -f2)

        echo -e "${BLUE}Cluster status: ${CLUSTER_STATUS}, Active nodes: ${ACTIVE_NODES}${NC}"

        # Check if cluster is green or yellow (yellow is acceptable for single-node or during startup)
        if [[ "$CLUSTER_STATUS" == "green" ]] || [[ "$CLUSTER_STATUS" == "yellow" ]]; then
            echo -e "${GREEN}✓ Elasticsearch cluster is ready (${CLUSTER_STATUS})${NC}"
            ES_READY=true
            break
        fi
    else
        # If curl fails, check if it's a connection issue or authentication issue
        HTTP_CODE=$(curl -s -w "%{http_code}" -o /dev/null --connect-timeout 5 --max-time 10 --cacert ./tls/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" "https://localhost:9200/_cluster/health" 2>/dev/null || echo "000")
        echo -e "${BLUE}HTTP response code: ${HTTP_CODE}${NC}"

        if [ "$HTTP_CODE" == "401" ]; then
            echo -e "${RED}✗ Authentication failed. Check ELASTIC_PASSWORD${NC}"
        elif [ "$HTTP_CODE" == "000" ]; then
            echo -e "${BLUE}Connection refused or timeout. Elasticsearch may still be starting...${NC}"
        fi
    fi

    sleep 15  # Increased from 10 seconds
    ((RETRY_COUNT++))
done

if [ "$ES_READY" != "true" ]; then
    echo -e "${RED}✗ Elasticsearch failed to start within expected time${NC}"
    echo -e "${YELLOW}Checking service logs for troubleshooting...${NC}"

    # Show service logs for debugging
    echo -e "${BLUE}=== Elasticsearch1 Service Logs ===${NC}"
    docker service logs --tail 20 elk_elasticsearch1 2>/dev/null || echo "No logs available"

    echo -e "${BLUE}=== Elasticsearch2 Service Logs ===${NC}"
    docker service logs --tail 20 elk_elasticsearch2 2>/dev/null || echo "No logs available"

    echo -e "${BLUE}=== Elasticsearch3 Service Logs ===${NC}"
    docker service logs --tail 20 elk_elasticsearch3 2>/dev/null || echo "No logs available"

    exit 1
fi

# Run setup for users and roles
echo -e "${YELLOW}Setting up Elasticsearch users and roles...${NC}"
docker compose up setup -d
sleep 3                                                                                               echo -e "${GREEN}✓ TLS certificates generated${NC}"
else
    echo -e "${GREEN}✓ TLS certificates found${NC}"
fi

echo -e "${GREEN}✓ Setup completed successfully!${NC}"
echo -e "${GREEN}✓ ELK Stack is now running in Docker Swarm mode${NC}"
echo -e "${YELLOW}Access Kibana at: https://localhost:5601${NC}"
echo -e "${YELLOW}Access Elasticsearch at: https://localhost:9200${NC}"

# Final status check
echo -e "${BLUE}=== Final Service Status ===${NC}"
docker service ls --filter name=elk_