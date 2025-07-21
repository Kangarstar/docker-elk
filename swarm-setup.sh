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

# Function to safely remove Docker stack
remove_stack() {
    if docker stack ls --format "{{.Name}}" | grep -q "^elk$"; then
        echo -e "${YELLOW}Removing existing ELK stack...${NC}"
        docker stack rm elk
        
        # Wait for stack to be completely removed
        echo -e "${YELLOW}Waiting for stack removal to complete...${NC}"
        while docker stack ls --format "{{.Name}}" | grep -q "^elk$"; do
            sleep 2
        done
        
        # Additional wait for resources cleanup
        sleep 10
        echo -e "${GREEN}✓ ELK stack removed${NC}"
    else
        echo -e "${BLUE}ℹ No existing ELK stack found${NC}"
    fi
}

# Function to safely remove and recreate secrets
update_secrets() {
    echo -e "${YELLOW}Updating Docker secrets for TLS certificates...${NC}"
    
    # List of secrets to manage
    local secrets=(
        "elk_ca_crt:./tls/certs/ca/ca.crt"
        "elk_elasticsearch_crt:./tls/certs/elasticsearch/elasticsearch.crt"
        "elk_elasticsearch_key:./tls/certs/elasticsearch/elasticsearch.key"
        "elk_kibana_crt:./tls/certs/kibana/kibana.crt"
        "elk_kibana_key:./tls/certs/kibana/kibana.key"
        "elk_fleet_crt:./tls/certs/fleet-server/fleet-server.crt"
        "elk_fleet_key:./tls/certs/fleet-server/fleet-server.key"
    )
    
    # Remove existing secrets if they exist (ignore errors)
    for secret_info in "${secrets[@]}"; do
        secret_name="${secret_info%%:*}"
        docker secret rm "$secret_name" 2>/dev/null || true
    done
    
    # Wait a moment for cleanup
    sleep 2
    
    # Create new secrets
    for secret_info in "${secrets[@]}"; do
        secret_name="${secret_info%%:*}"
        secret_file="${secret_info##*:}"
        if [ -f "$secret_file" ]; then
            docker secret create "$secret_name" "$secret_file"
        else
            echo -e "${RED}✗ Warning: $secret_file not found for secret $secret_name${NC}"
        fi
    done
    
    echo -e "${GREEN}✓ Docker secrets updated${NC}"
}

# Function to safely remove and recreate configs
update_configs() {
    echo -e "${YELLOW}Updating Docker configs...${NC}"
    
    # List of configs to manage
    local configs=(
        "kibana_yml:./kibana/config/kibana.yml"
        "metricbeat_yml:./extensions/metricbeat/config/metricbeat.yml"
        "filebeat_yml:./extensions/filebeat/config/filebeat.yml"
        "logstash_yml:./logstash/config/logstash.yml"
        "pipeline_conf:./logstash/pipeline/logstash.conf"
    )
    
    # Remove existing configs if they exist (ignore errors)
    for config_info in "${configs[@]}"; do
        config_name="${config_info%%:*}"
        docker config rm "$config_name" 2>/dev/null || true
    done
    
    # Wait a moment for cleanup
    sleep 2
    
    # Create new configs
    for config_info in "${configs[@]}"; do
        config_name="${config_info%%:*}"
        config_file="${config_info##*:}"
        if [ -f "$config_file" ]; then
            docker config create "$config_name" "$config_file"
        else
            echo -e "${RED}✗ Warning: $config_file not found for config $config_name${NC}"
        fi
    done
    
    echo -e "${GREEN}✓ Docker configs updated${NC}"
}

# Check if this is a rerun (stack exists)
STACK_EXISTS=false
if docker stack ls --format "{{.Name}}" | grep -q "^elk$"; then
    STACK_EXISTS=true
    echo -e "${BLUE}ℹ Existing ELK stack detected - performing restart and update${NC}"
fi

# If stack exists, remove it first
if [ "$STACK_EXISTS" = true ]; then
    remove_stack
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

# Update secrets and configs (now safe since stack is removed)
update_secrets
update_configs

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

# Wait for services to start
echo -e "${YELLOW}Waiting for services to start...${NC}"
# sleep 20

# Wait for Elasticsearch cluster to be ready
echo -e "${YELLOW}Waiting for Elasticsearch cluster to be ready...${NC}"
echo -e "${BLUE}This may take several minutes for a 3-node cluster...${NC}"

# Enhanced readiness check with better error reporting
MAX_RETRIES=40
RETRY_COUNT=0
ES_READY=false

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    echo -e "${YELLOW}Checking Elasticsearch readiness... (${RETRY_COUNT}/${MAX_RETRIES})${NC}"

    # Check if Elasticsearch is responding
    if curl -4 -s --connect-timeout 5 --max-time 10 --cacert ./tls/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" "https://localhost:9200/_cluster/health" > /tmp/es_health.json 2>/dev/null; then
        # Check if we got a valid JSON response with the required fields
        if [ -s /tmp/es_health.json ] && grep -q '"status"' /tmp/es_health.json && grep -q '"number_of_nodes"' /tmp/es_health.json; then
            CLUSTER_STATUS=$(cat /tmp/es_health.json | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
            ACTIVE_NODES=$(cat /tmp/es_health.json | grep -o '"number_of_nodes":[0-9]*' | cut -d':' -f2)

            # Only proceed if we successfully extracted both values
            if [[ -n "$CLUSTER_STATUS" ]] && [[ -n "$ACTIVE_NODES" ]]; then
                echo -e "${BLUE}Cluster status: ${CLUSTER_STATUS}, Active nodes: ${ACTIVE_NODES}${NC}"

                # Check if cluster is green or yellow (yellow is acceptable for single-node or during startup)
                if [[ "$CLUSTER_STATUS" == "green" ]] || [[ "$CLUSTER_STATUS" == "yellow" ]]; then
                    echo -e "${GREEN}✓ Elasticsearch cluster is ready (${CLUSTER_STATUS})${NC}"
                    ES_READY=true
                    break
                else
                    echo -e "${BLUE}Cluster not ready yet (status: ${CLUSTER_STATUS})${NC}"
                fi
            else
                echo -e "${BLUE}Incomplete response data, continuing to wait...${NC}"
            fi
        else
            echo -e "${BLUE}Empty or invalid response, Elasticsearch may still be starting...${NC}"
        fi
    else
        # If curl fails, check if it's a connection issue or authentication issue
        HTTP_CODE=$(curl -4 -s -w "%{http_code}" -o /dev/null --connect-timeout 5 --max-time 10 --cacert ./tls/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" "https://localhost:9200/_cluster/health" 2>/dev/null || echo "000")
        
        # Clean up HTTP_CODE in case of multiple 000s or other issues
        HTTP_CODE=$(echo "$HTTP_CODE" | tail -c 4)
        
        echo -e "${BLUE}HTTP response code: ${HTTP_CODE}${NC}"

        if [ "$HTTP_CODE" == "401" ]; then
            echo -e "${RED}✗ Authentication failed. Check ELASTIC_PASSWORD${NC}"
            break
        elif [ "$HTTP_CODE" == "000" ]; then
            echo -e "${BLUE}Connection refused or timeout. Elasticsearch may still be starting...${NC}"
        else
            echo -e "${BLUE}Received HTTP ${HTTP_CODE}, continuing to wait...${NC}"
        fi
    fi

    # Always increment counter and sleep at the end of the loop
    ((RETRY_COUNT++))
    echo -e "${BLUE}Waiting 5 seconds before next check... (attempt ${RETRY_COUNT}/${MAX_RETRIES})${NC}"
    sleep 5
done

if [ "$ES_READY" = false ]; then
    echo -e "${RED}✗ Elasticsearch failed to become ready within the timeout period${NC}"
    echo -e "${YELLOW}You can check the service status with: docker service ls --filter name=elk_${NC}"
    echo -e "${YELLOW}And check logs with: docker service logs elk_elasticsearch1${NC}"
    exit 1
fi
# ========================================
# ELASTICSEARCH USER SETUP INTEGRATION
# ========================================

echo -e "${GREEN}=== Setting up Elasticsearch Users and Roles ===${NC}"

# Override functions for TLS support
function wait_for_elasticsearch {
    local elasticsearch_host="127.0.0.1"  # Using port forwarding
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
    local elasticsearch_host="127.0.0.1"
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
    local elasticsearch_host="127.0.0.1"

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
    local elasticsearch_host="127.0.0.1"

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
    local elasticsearch_host="127.0.0.1"

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
    local elasticsearch_host="127.0.0.1"

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
if [ "$STACK_EXISTS" = true ]; then
    echo -e "${GREEN}✓ ELK Stack has been restarted and updated in Docker Swarm mode${NC}"
else
    echo -e "${GREEN}✓ ELK Stack is now running in Docker Swarm mode${NC}"
fi
echo -e "${YELLOW}Access Kibana at: https://localhost:5601${NC}"

# Final status check
echo -e "${BLUE}=== Final Service Status ===${NC}"
docker service ls --filter name=elk_

# Cleanup temporary files
rm -f /tmp/es_health.json 2>/dev/null || true