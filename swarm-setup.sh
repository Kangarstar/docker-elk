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

# Deploy the stack
echo -e "${YELLOW}Deploying ELK stack...${NC}"
docker stack deploy -c docker-stack.yml elk

# Wait for services to be deployed
echo -e "${YELLOW}Waiting for services to start...${NC}"
sleep 30

# Check if services are deployed
echo -e "${YELLOW}Checking if Elasticsearch services are running...${NC}"
SERVICES_RUNNING=false
for i in {1..20}; do
    ES_SERVICES=$(docker service ls --filter name=elk_elasticsearch --format "{{.Replicas}}" | grep -c "1/1" || echo "0")
    if [ "$ES_SERVICES" -ge 1 ]; then
        echo -e "${GREEN}✓ Elasticsearch services are running${NC}"
        SERVICES_RUNNING=true
        break
    fi
    echo -e "${BLUE}Services starting... ($i/20)${NC}"
    sleep 15
done

if [ "$SERVICES_RUNNING" = "false" ]; then
    echo -e "${RED}✗ Elasticsearch services failed to start${NC}"
    echo -e "${YELLOW}Check service status: docker service ls --filter name=elk_${NC}"
    exit 1
fi

# ========================================
# ELASTICSEARCH USER SETUP INTEGRATION
# ========================================

echo -e "${GREEN}=== Setting up Elasticsearch Users and Roles ===${NC}"

# Get the Elasticsearch service endpoint
# Option 1: Use docker service inspect to get the published port
ES_PORT=$(docker service inspect elk_elasticsearch --format='{{range .Spec.EndpointSpec.Ports}}{{if eq .TargetPort 9200}}{{.PublishedPort}}{{end}}{{end}}' 2>/dev/null || echo "9200")

# Option 2: Alternative - run setup inside a container connected to the elk network
function run_curl_in_network {
    local url=$1
    local method=${2:-GET}
    local data=${3:-}
    local auth_header=""
    
    if [[ -n "${ELASTIC_PASSWORD:-}" ]]; then
        auth_header="-u elastic:${ELASTIC_PASSWORD}"
    fi
    
    local curl_args="--insecure --cacert /certs/ca.crt -s -D- -m15"
    if [[ "$method" != "GET" ]]; then
        curl_args="$curl_args -X $method"
    fi
    if [[ -n "$data" ]]; then
        curl_args="$curl_args -H 'Content-Type: application/json' -d '$data'"
    fi
    
    # Run curl inside a container connected to the elk network
    docker run --rm --network elk \
        -v "$(pwd)/tls/certs/ca:/certs:ro" \
        curlimages/curl:latest \
        sh -c "curl $curl_args $auth_header '$url'" 2>/dev/null
}

# Modified functions to work with Docker Swarm
function wait_for_elasticsearch {
    local elasticsearch_host="elk_elasticsearch"  # Use service name
    local url="https://${elasticsearch_host}:9200/"
    
    local -i result=1
    local output

    echo -e "${BLUE}Waiting for Elasticsearch to be ready...${NC}"
    
    # retry for max 300s (60*5s)
    for i in $(seq 1 60); do
        echo -e "${BLUE}Attempt $i/60...${NC}"
        
        output=$(run_curl_in_network "$url")
        
        if [[ "${output: -3}" -eq 200 ]]; then
            result=0
            echo -e "${GREEN}✓ Elasticsearch is ready${NC}"
            break
        fi
        
        echo -e "${BLUE}Elasticsearch not ready yet, waiting...${NC}"
        sleep 5
    done

    if ((result)); then
        echo -e "${RED}✗ Elasticsearch failed to become ready${NC}"
        if [[ -n "$output" ]]; then
            echo -e "${RED}Last response: ${output}${NC}"
        fi
    fi

    return $result
}

function wait_for_builtin_users {
    local elasticsearch_host="elk_elasticsearch"
    local url="https://${elasticsearch_host}:9200/_security/user?pretty"
    
    local -i result=1
    local output
    local -i num_users

    echo -e "${BLUE}Waiting for built-in users initialization...${NC}"

    # retry for max 60s (60*1s)
    for i in $(seq 1 60); do
        echo -e "${BLUE}Checking built-in users ($i/60)...${NC}"
        
        num_users=0
        output=$(run_curl_in_network "$url")
        
        # Count reserved users in the output
        num_users=$(echo "$output" | grep -c "_reserved.*true" || echo "0")
        
        # Check if we got a successful response and have multiple users
        if [[ "${output: -3}" -eq 200 ]] && (( num_users > 1 )); then
            result=0
            echo -e "${GREEN}✓ Built-in users are initialized${NC}"
            break
        fi
        
        sleep 1
    done

    if ((result)); then
        echo -e "${RED}✗ Built-in users failed to initialize${NC}"
        echo -e "${RED}Last response: ${output}${NC}"
    fi

    return $result
}

function check_user_exists {
    local username=$1
    local elasticsearch_host="elk_elasticsearch"
    local url="https://${elasticsearch_host}:9200/_security/user/${username}"

    local output
    output=$(run_curl_in_network "$url")
    
    if [[ "${output: -3}" -eq 200 ]]; then
        echo "1"  # User exists
    elif [[ "${output: -3}" -eq 404 ]]; then
        echo "0"  # User doesn't exist
    else
        echo -e "${RED}Error checking user: ${output}${NC}" >&2
        echo "0"
    fi
}

function set_user_password {
    local username=$1
    local password=$2
    local elasticsearch_host="elk_elasticsearch"
    local url="https://${elasticsearch_host}:9200/_security/user/${username}/_password"
    local data="{\"password\": \"${password}\"}"

    local output
    output=$(run_curl_in_network "$url" "POST" "$data")
    
    if [[ "${output: -3}" -eq 200 ]]; then
        return 0
    else
        echo -e "${RED}Failed to set password for user ${username}: ${output}${NC}" >&2
        return 1
    fi
}

function create_user {
    local username=$1
    local password=$2
    local role=$3
    local elasticsearch_host="elk_elasticsearch"
    local url="https://${elasticsearch_host}:9200/_security/user/${username}"
    local data="{\"password\":\"${password}\",\"roles\":[\"${role}\"]}"

    local output
    output=$(run_curl_in_network "$url" "POST" "$data")
    
    if [[ "${output: -3}" -eq 200 ]]; then
        return 0
    else
        echo -e "${RED}Failed to create user ${username}: ${output}${NC}" >&2
        return 1
    fi
}

function ensure_role {
    local name=$1
    local body=$2
    local elasticsearch_host="elk_elasticsearch"
    local url="https://${elasticsearch_host}:9200/_security/role/${name}"

    local output
    output=$(run_curl_in_network "$url" "POST" "$body")
    
    if [[ "${output: -3}" -eq 200 ]]; then
        return 0
    else
        echo -e "${RED}Failed to create/update role ${name}: ${output}${NC}" >&2
        return 1
    fi
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

# Wait for Elasticsearch to be ready
log 'Waiting for Elasticsearch to be ready'
declare -i exit_code=0
wait_for_elasticsearch || exit_code=$?

if ((exit_code)); then
    suberr 'Timed out waiting for Elasticsearch'
    exit $exit_code
fi

sublog 'Elasticsearch is ready'

# Wait for built-in users
log 'Waiting for built-in users initialization'
exit_code=0
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