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
echo -e "${BLUE}This may take several minutes for a 3-node cluster...${NC}"

# Simple readiness check
MAX_RETRIES=20
RETRY_COUNT=0
ES_READY=false

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if [ $((RETRY_COUNT % 5)) -eq 0 ]; then
        echo -e "${YELLOW}Checking Elasticsearch readiness... (attempt $((RETRY_COUNT + 1))/${MAX_RETRIES})${NC}"
    fi

    # Simple health check
    if curl -s --connect-timeout 10 --max-time 15 \
            --cacert ./tls/certs/ca/ca.crt \
            -u "elastic:${ELASTIC_PASSWORD}" \
            "https://localhost:9200/_cluster/health" > /tmp/es_health.json 2>/dev/null; then
        
        # Extract cluster status
        if command -v jq >/dev/null 2>&1; then
            CLUSTER_STATUS=$(jq -r '.status' /tmp/es_health.json 2>/dev/null)
        else
            CLUSTER_STATUS=$(grep -o '"status":"[^"]*"' /tmp/es_health.json | cut -d'"' -f4)
        fi

        # Check if cluster is healthy
        if [[ "$CLUSTER_STATUS" == "green" ]] || [[ "$CLUSTER_STATUS" == "yellow" ]]; then
            echo -e "${GREEN}✓ Elasticsearch cluster is ready (status: ${CLUSTER_STATUS})${NC}"
            ES_READY=true
            break
        else
            echo -e "${BLUE}Cluster status: ${CLUSTER_STATUS}, waiting...${NC}"
        fi
    fi

    sleep 10
    ((RETRY_COUNT++))
done

# Clean up temp file
rm -f /tmp/es_health.json

if [ "$ES_READY" != "true" ]; then
    echo -e "${RED}✗ Elasticsearch failed to start within expected time${NC}"
    echo -e "${YELLOW}Checking if services are running...${NC}"
    
    # Quick service status check
    if docker service ls --filter name=elk_elasticsearch --format "table {{.Name}}\t{{.Replicas}}" | grep -q "0/"; then
        echo -e "${RED}Some Elasticsearch services are not running${NC}"
        echo -e "${YELLOW}Run 'docker service logs elk_elasticsearch1' for more details${NC}"
    else
        echo -e "${BLUE}Services appear to be running, but cluster is not ready${NC}"
        echo -e "${YELLOW}This might be normal for initial startup. Try accessing Kibana in a few minutes.${NC}"
    fi
    
    # Don't exit on re-runs if services are deployed
    if docker service ls --filter name=elk_ --quiet | wc -l | grep -q "^[1-9]"; then
        echo -e "${YELLOW}ELK services are deployed. Continuing with user setup...${NC}"
    else
        exit 1
    fi
fi

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

# ========================================
# ELASTICSEARCH USER SETUP INTEGRATION
# ========================================

echo -e "${GREEN}=== Setting up Elasticsearch Users and Roles ===${NC}"

# Override functions for TLS support
function wait_for_elasticsearch {
    local elasticsearch_host="localhost"  # Using port forwarding
    local -a args=( '-s' '-D-' '-m15' '-w' '%{http_code}' 
        "--cacert" "./tls/certs/ca/ca.crt"
        "https://${elasticsearch_host}:9200/" )

    if [[ -n "${ELASTIC_PASSWORD:-}" ]]; then
        args+=( '-u' "elastic:${ELASTIC_PASSWORD}" )
    fi

    local -i result=1
    local output

    # retry for max 300s (60*5s)
    for _ in $(seq 1 60); do
        local -i exit_code=0
        output="$(curl "${args[@]}")" || exit_code=$?

        if ((exit_code)); then
            result=$exit_code
        fi

        if [[ "${output: -3}" -eq 200 ]]; then
            result=0
            break
        fi

        sleep 5
    done

    if ((result)) && [[ "${output: -3}" -ne 000 ]]; then
        echo -e "\n${output::-3}"
    fi

    return $result
}

function wait_for_builtin_users {
    local elasticsearch_host="localhost"
    local -a args=( '-s' '-D-' '-m15' 
        "--cacert" "./tls/certs/ca/ca.crt"
        "https://${elasticsearch_host}:9200/_security/user?pretty" )

    if [[ -n "${ELASTIC_PASSWORD:-}" ]]; then
        args+=( '-u' "elastic:${ELASTIC_PASSWORD}" )
    fi

    local -i result=1
    local line
    local -i exit_code
    local -i num_users

    # retry for max 30s (30*1s)
    for _ in $(seq 1 30); do
        num_users=0

        while IFS= read -r line || ! exit_code="$line"; do
            if [[ "$line" =~ _reserved.+true ]]; then
                (( num_users++ ))
            fi
        done < <(curl "${args[@]}"; printf '%s' "$?")

        if ((exit_code)); then
            result=$exit_code
        fi

        # we expect more than just the 'elastic' user in the result
        if (( num_users > 1 )); then
            result=0
            break
        fi

        sleep 1
    done

    return $result
}

function check_user_exists {
    local username=$1
    local elasticsearch_host="localhost"

    local -a args=( '-s' '-D-' '-m15' '-w' '%{http_code}'
        "--cacert" "./tls/certs/ca/ca.crt"
        "https://${elasticsearch_host}:9200/_security/user/${username}"
        )

    if [[ -n "${ELASTIC_PASSWORD:-}" ]]; then
        args+=( '-u' "elastic:${ELASTIC_PASSWORD}" )
    fi

    local -i result=1
    local -i exists=0
    local output

    output="$(curl "${args[@]}")"
    if [[ "${output: -3}" -eq 200 || "${output: -3}" -eq 404 ]]; then
        result=0
    fi
    if [[ "${output: -3}" -eq 200 ]]; then
        exists=1
    fi

    if ((result)); then
        echo -e "\n${output::-3}"
    else
        echo "$exists"
    fi

    return $result
}

function set_user_password {
    local username=$1
    local password=$2
    local elasticsearch_host="localhost"

    local -a args=( '-s' '-D-' '-m15' '-w' '%{http_code}'
        "--cacert" "./tls/certs/ca/ca.crt"
        "https://${elasticsearch_host}:9200/_security/user/${username}/_password"
        '-X' 'POST'
        '-H' 'Content-Type: application/json'
        '-d' "{\"password\" : \"${password}\"}"
        )

    if [[ -n "${ELASTIC_PASSWORD:-}" ]]; then
        args+=( '-u' "elastic:${ELASTIC_PASSWORD}" )
    fi

    local -i result=1
    local output

    output="$(curl "${args[@]}")"
    if [[ "${output: -3}" -eq 200 ]]; then
        result=0
    fi

    if ((result)); then
        echo -e "\n${output::-3}\n"
    fi

    return $result
}

function create_user {
    local username=$1
    local password=$2
    local role=$3
    local elasticsearch_host="localhost"

    local -a args=( '-s' '-D-' '-m15' '-w' '%{http_code}'
        "--cacert" "./tls/certs/ca/ca.crt"
        "https://${elasticsearch_host}:9200/_security/user/${username}"
        '-X' 'POST'
        '-H' 'Content-Type: application/json'
        '-d' "{\"password\":\"${password}\",\"roles\":[\"${role}\"]}"
        )

    if [[ -n "${ELASTIC_PASSWORD:-}" ]]; then
        args+=( '-u' "elastic:${ELASTIC_PASSWORD}" )
    fi

    local -i result=1
    local output

    output="$(curl "${args[@]}")"
    if [[ "${output: -3}" -eq 200 ]]; then
        result=0
    fi

    if ((result)); then
        echo -e "\n${output::-3}\n"
    fi

    return $result
}

function ensure_role {
    local name=$1
    local body=$2
    local elasticsearch_host="localhost"

    local -a args=( '-s' '-D-' '-m15' '-w' '%{http_code}'
        "--cacert" "./tls/certs/ca/ca.crt"
        "https://${elasticsearch_host}:9200/_security/role/${name}"
        '-X' 'POST'
        '-H' 'Content-Type: application/json'
        '-d' "$body"
        )

    if [[ -n "${ELASTIC_PASSWORD:-}" ]]; then
        args+=( '-u' "elastic:${ELASTIC_PASSWORD}" )
    fi

    local -i result=1
    local output

    output="$(curl "${args[@]}")"
    if [[ "${output: -3}" -eq 200 ]]; then
        result=0
    fi

    if ((result)); then
        echo -e "\n${output::-3}\n"
    fi

    return $result
}

# Users declarations
declare -A users_passwords
users_passwords=(
    [logstash_internal]="${LOGSTASH_INTERNAL_PASSWORD:-}"
    [kibana_system]="${KIBANA_SYSTEM_PASSWORD:-}"
    [metricbeat_internal]="${METRICBEAT_INTERNAL_PASSWORD:-}"
    [filebeat_internal]="${FILEBEAT_INTERNAL_PASSWORD:-}"
    [heartbeat_internal]="${HEARTBEAT_INTERNAL_PASSWORD:-}"
    [monitoring_internal]="${MONITORING_INTERNAL_PASSWORD:-}"
    [beats_system]="${BEATS_SYSTEM_PASSWORD:-}"
)

declare -A users_roles
users_roles=(
    [logstash_internal]='logstash_writer'
    [metricbeat_internal]='metricbeat_writer'
    [filebeat_internal]='filebeat_writer'
    [heartbeat_internal]='heartbeat_writer'
    [monitoring_internal]='remote_monitoring_collector'
)

declare -A roles_files
roles_files=(
    [logstash_writer]='logstash_writer.json'
    [metricbeat_writer]='metricbeat_writer.json'
    [filebeat_writer]='filebeat_writer.json'
    [heartbeat_writer]='heartbeat_writer.json'
)

log 'Waiting for built-in users initialization'
declare -i exit_code=0
wait_for_builtin_users || exit_code=$?

if ((exit_code)); then
    suberr 'Timed out waiting for built-in users'
    exit $exit_code
fi

sublog 'Built-in users were initialized'

# Create roles
for role in "${!roles_files[@]}"; do
    log "Role '$role'"
    
    declare body_file
    body_file="${PWD}/setup/roles/${roles_files[$role]:-}"
    if [[ ! -f "${body_file:-}" ]]; then
        sublog "No role body found at '${body_file}', skipping"
        continue
    fi
    
    sublog 'Creating/updating'
    ensure_role "$role" "$(<"${body_file}")"
done

# Create/update users
for user in "${!users_passwords[@]}"; do
    log "User '$user'"
    if [[ -z "${users_passwords[$user]:-}" ]]; then
        sublog 'No password defined, skipping'
        continue
    fi
    
    declare -i user_exists=0
    user_exists="$(check_user_exists "$user")"
    
    if ((user_exists)); then
        sublog 'User exists, setting password'
        set_user_password "$user" "${users_passwords[$user]}"
    else
        if [[ -z "${users_roles[$user]:-}" ]]; then
            suberr 'No role defined, skipping creation'
            continue
        fi

        sublog 'User does not exist, creating'
        create_user "$user" "${users_passwords[$user]}" "${users_roles[$user]}"
    fi
done

echo -e "${GREEN}✓ Elasticsearch users and roles setup completed!${NC}"

echo -e "${GREEN}✓ Setup completed successfully!${NC}"
echo -e "${GREEN}✓ ELK Stack is now running in Docker Swarm mode${NC}"
echo -e "${YELLOW}Access Kibana at: https://localhost:5601${NC}"
echo -e "${YELLOW}Access Elasticsearch at: https://localhost:9200${NC}"

# Final status check
echo -e "${BLUE}=== Final Service Status ===${NC}"
docker service ls --filter name=elk_
