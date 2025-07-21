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
#    export $(cat .env | grep -v '#' | awk '/=/ {print $1}')
	set -a
	source .env
	set +a
    echo -e "${GREEN}✓ Loaded environment variables${NC}"
else
    echo -e "${RED}✗ .env file not found${NC}"
    exit 1
fi

# Source the library functions for Elasticsearch setup
if [ -f "./setup/lib.sh" ]; then
    source ./setup/lib.sh
    echo -e "${GREEN}✓ Loaded Elasticsearch setup functions${NC}"
else
    echo -e "${RED}✗ lib.sh not found${NC}"
    exit 1
fi

# Check if TLS certificates exist
if [ ! -f "./tls/certs/ca/ca.crt" ]; then
    echo -e "${YELLOW}⚠ TLS certificates not found. Running TLS setup...${NC}"
    sudo docker compose up tls -d
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
docker secret rm elk_fleet_crt 2>/dev/null || true
docker secret rm elk_fleet_key 2>/dev/null || true

# Create new secrets
docker secret create elk_ca_crt ./tls/certs/ca/ca.crt
docker secret create elk_elasticsearch_crt ./tls/certs/elasticsearch/elasticsearch.crt
docker secret create elk_elasticsearch_key ./tls/certs/elasticsearch/elasticsearch.key
docker secret create elk_kibana_crt ./tls/certs/kibana/kibana.crt
docker secret create elk_kibana_key ./tls/certs/kibana/kibana.key
docker secret create elk_fleet_crt ./tls/certs/fleet-server/fleet-server.crt
docker secret create elk_fleet_key ./tls/certs/fleet-server/fleet-server.key

# Remove existing configs if they exist (ignore errors)
docker config rm kibana_yml 2>/dev/null || true
docker config rm metricbeat_yml 2>/dev/null || true
docker config rm filebeat_yml 2>/dev/null || true
docker config rm logstash_yml 2>/dev/null || true
docker config rm pipeline_conf 2>/dev/null || true

# Create new configs
docker config create kibana_yml ./kibana/config/kibana.yml
docker config create metricbeat_yml ./extensions/metricbeat/config/metricbeat.yml
docker config create filebeat_yml ./extensions/filebeat/config/filebeat.yml
docker config create logstash_yml ./logstash/config/logstash.yml
docker config create pipeline_conf ./logstash/pipeline/logstash.conf

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

echo -e "${YELLOW}Waiting for Elasticsearch cluster to be ready...${NC}"

# Deploy the stack
echo -e "${YELLOW}Deploying ELK stack...${NC}"
docker stack deploy -d -c docker-stack.yml elk

# Simple wait and basic check
echo -e "${YELLOW}Waiting for services to start...${NC}"
sleep 30

echo -e "${YELLOW}Checking if Elasticsearch services are running...${NC}"

# Check if services are deployed (not necessarily ready)
SERVICES_RUNNING=false
for i in {1..10}; do
    ES_SERVICES=$(docker service ls --filter name=elk_elasticsearch --format "{{.Replicas}}" | grep -c "1/1" || echo "0")
    if [ "$ES_SERVICES" -ge 1 ]; then
        echo -e "${GREEN}✓ Elasticsearch services are running${NC}"
        SERVICES_RUNNING=true
        break
    fi
    echo -e "${BLUE}Services starting... ($i/10)${NC}"
    sleep 15
done

if [ "$SERVICES_RUNNING" = "false" ]; then
    echo -e "${RED}✗ Elasticsearch services failed to start${NC}"
    echo -e "${YELLOW}Check service status: docker service ls --filter name=elk_${NC}"
    exit 1
fi

# Simple connectivity test using status endpoints
echo -e "${YELLOW}Testing service connectivity...${NC}"

# Test Elasticsearch status
for i in {1..5}; do
    if curl -sf --insecure https://elasticsearch:5601 >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Elasticsearch is responding${NC}"
        break
    fi

    if [ $i -eq 5 ]; then
        echo -e "${YELLOW}⚠ Elasticsearch not responding yet, but continuing setup...${NC}"
        echo -e "${BLUE}The cluster may need more time to fully initialize${NC}"
    else
        echo -e "${BLUE}Waiting for Elasticsearch...${NC}"
        sleep 20
    fi
done

# Test Kibana status
for i in {1..5}; do
    if curl -sf --insecure https://kibana:5601/api/status >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Kibana is responding${NC}"
        break
    fi

    if [ $i -eq 5 ]; then
        echo -e "${YELLOW}⚠ Kibana not responding yet, but continuing setup...${NC}"
    else
        echo -e "${BLUE}Waiting for Kibana...${NC}"
        sleep 20
    fi
done

# Simple user creation function
function create_or_update_user_simple {
    local username=$1
    local password=$2
    local role=$3

    echo -e "${YELLOW}Setting up user: $username${NC}"

    if curl -sf --connect-timeout 10 --max-time 15 \
            --cacert ./tls/certs/ca/ca.crt \
            -u "elastic:${ELASTIC_PASSWORD}" \
            -X POST \
            -H "Content-Type: application/json" \
            -d "{\"password\":\"${password}\",\"roles\":[\"${role}\"]}" \
            "https://localhost:9200/_security/user/${username}" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ User $username configured${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ Failed to configure user $username${NC}"
        return 1
    fi
}

# Simple role creation function
function create_role_simple {
    local role_name=$1
    local role_file=$2

    if [[ -f "$role_file" ]]; then
        echo -e "${YELLOW}Setting up role: $role_name${NC}"

        if curl -sf --connect-timeout 10 --max-time 15 \
                --cacert ./tls/certs/ca/ca.crt \
                -u "elastic:${ELASTIC_PASSWORD}" \
                -X POST \
                -H "Content-Type: application/json" \
                -d "@${role_file}" \
                "https://localhost:9200/_security/role/${role_name}" >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Role $role_name configured${NC}"
        else
            echo -e "${YELLOW}⚠ Failed to configure role $role_name${NC}"
        fi
    fi
}

# Create roles
echo -e "${YELLOW}Creating roles...${NC}"
create_role_simple "logstash_writer" "./setup/roles/logstash_writer.json"
create_role_simple "metricbeat_writer" "./setup/roles/metricbeat_writer.json"
create_role_simple "filebeat_writer" "./setup/roles/filebeat_writer.json"
create_role_simple "heartbeat_writer" "./setup/roles/heartbeat_writer.json"

# Create/update users
echo -e "${YELLOW}Creating users...${NC}"
[[ -n "${LOGSTASH_INTERNAL_PASSWORD:-}" ]] && create_or_update_user_simple "logstash_internal" "${LOGSTASH_INTERNAL_PASSWORD}" "logstash_writer"
[[ -n "${KIBANA_SYSTEM_PASSWORD:-}" ]] && create_or_update_user_simple "kibana_system" "${KIBANA_SYSTEM_PASSWORD}" "kibana_system"
[[ -n "${METRICBEAT_INTERNAL_PASSWORD:-}" ]] && create_or_update_user_simple "metricbeat_internal" "${METRICBEAT_INTERNAL_PASSWORD}" "metricbeat_writer"
[[ -n "${FILEBEAT_INTERNAL_PASSWORD:-}" ]] && create_or_update_user_simple "filebeat_internal" "${FILEBEAT_INTERNAL_PASSWORD}" "filebeat_writer"
[[ -n "${HEARTBEAT_INTERNAL_PASSWORD:-}" ]] && create_or_update_user_simple "heartbeat_internal" "${HEARTBEAT_INTERNAL_PASSWORD}" "heartbeat_writer"
[[ -n "${MONITORING_INTERNAL_PASSWORD:-}" ]] && create_or_update_user_simple "monitoring_internal" "${MONITORING_INTERNAL_PASSWORD}" "remote_monitoring_collector"
[[ -n "${BEATS_SYSTEM_PASSWORD:-}" ]] && create_or_update_user_simple "beats_system" "${BEATS_SYSTEM_PASSWORD}" "beats_system"

echo -e "${GREEN}✓ User setup completed${NC}"
echo -e "${GREEN}✓ Setup completed successfully!${NC}"
echo -e "${GREEN}✓ ELK Stack is now running in Docker Swarm mode${NC}"
echo -e "${YELLOW}Access Kibana at: https://localhost:5601${NC}"

# Final status check
echo -e "${BLUE}=== Final Service Status ===${NC}"
docker service ls --filter name=elk_
