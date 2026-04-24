#!/usr/bin/bats
TEST_CONTAINER=${TEST_CONTAINER:-bci-init-build.docker}
TEST_BINARY=${TEST_BINARY:-/usr/bin/systemd-mcp}

setup_file() {
  export BATS_LIB_PATH=${BATS_LIB_PATH:-/usr/lib}
  
  export NETWORK_NAME="mcp-test-net-$(date +%s)-$RANDOM"
  export CONTAINER_NAME="systemd-mcp-keycloak-$(date +%s)-$RANDOM"
  export KEYCLOAK_CONTAINER="keycloak-$(date +%s)-$RANDOM"
  
  cd ${BATS_TEST_DIRNAME}/../
  
  # Ensure we have the binary and tarball
  make build dist certs test-client
  cp systemd-mcp.tar.gz ${BATS_TEST_DIRNAME}
  
  cd ${BATS_TEST_DIRNAME}
  # Rebuild the image to ensure it has the latest changes
  podman build -t systemd-mcp-bci -f $TEST_CONTAINER .
  
  podman network create $NETWORK_NAME || {
    echo "# Failed to create network $NETWORK_NAME" >&3
    return 1
  }
  
  # 1. Start Keycloak
  podman run -d --name $KEYCLOAK_CONTAINER --network $NETWORK_NAME \
    -p 8080 \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
    -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
    -v ${BATS_TEST_DIRNAME}/../config.json:/opt/keycloak/data/import/realm.json:Z \
    quay.io/keycloak/keycloak:latest start-dev --import-realm
    
  # Find host port for Keycloak
  KC_PORT=$(podman port $KEYCLOAK_CONTAINER 8080 | awk -F: '{print $NF}' | head -n1)
  
  # 2. Wait for Keycloak
  echo "# Waiting for Keycloak on port $KC_PORT..." >&3
  for i in {1..120}; do
    if curl -s http://localhost:${KC_PORT}/realms/mcp-realm > /dev/null; then
      echo "# Keycloak is ready" >&3
      break
    fi
    if [ $i -eq 120 ]; then
      echo "# Keycloak failed to start" >&3
      return 1
    fi
    sleep 2
  done
  
  # Internal URL for systemd-mcp container to reach Keycloak
  export INTERNAL_CONTROLLER_URL="http://${KEYCLOAK_CONTAINER}:8080/realms/mcp-realm"
  
  # External URLs for curl from the host
  export TOKEN_URL="http://localhost:${KC_PORT}/realms/mcp-realm/protocol/openid-connect/token"
  
  # 3. Start systemd-mcp container
  podman run -d --name $CONTAINER_NAME --network $NETWORK_NAME --privileged \
    -p 8080 \
    -v ${BATS_TEST_DIRNAME}/../server.crt:/etc/ssl/certs/server.crt:Z \
    -v ${BATS_TEST_DIRNAME}/../server.key:/etc/ssl/private/server.key:Z \
    systemd-mcp-bci
    
  # 4. Wait for systemd
  echo "# Waiting for systemd..." >&3
  for i in {1..30}; do
    if podman exec $CONTAINER_NAME systemctl is-system-running | grep -qE "running|degraded"; then
      echo "# systemd is ready" >&3
      break
    fi
    sleep 1
  done
  
  # 5. Configure systemd-mcp service inside the container
  # We use the internal network name for the controller URL
  SERVICE_FILE="[Unit]
Description=Systemd MCP Server
After=network.target

[Service]
ExecStart=$TEST_BINARY --http :8080 --controller ${INTERNAL_CONTROLLER_URL} --cert-file /etc/ssl/certs/server.crt --key-file /etc/ssl/private/server.key --log-json --debug --verbose --skip-tls-verify
Restart=always

[Install]
WantedBy=multi-user.target
"
  echo "$SERVICE_FILE" | podman exec -i $CONTAINER_NAME bash -c "cat > /etc/systemd/system/systemd-mcp.service"
  podman exec $CONTAINER_NAME systemctl daemon-reload
  podman exec $CONTAINER_NAME systemctl enable --now systemd-mcp
  
  # 6. Wait for systemd-mcp
  echo "# Waiting for systemd-mcp..." >&3
  for i in {1..30}; do
    if podman exec $CONTAINER_NAME systemctl is-active systemd-mcp > /dev/null; then
      echo "# systemd-mcp is active" >&3
      break
    fi
    sleep 1
  done
  
  MCP_PORT=$(podman port $CONTAINER_NAME 8080 | awk -F: '{print $NF}' | head -n1)
  export MCP_URL="https://localhost:${MCP_PORT}/mcp"
}

teardown_file() {
  podman rm -f $CONTAINER_NAME || true
  podman rm -f $KEYCLOAK_CONTAINER || true
  podman network rm $NETWORK_NAME || true
  rm -f ${BATS_TEST_DIRNAME}/systemd-mcp.tar.gz
  podman image rm systemd-mcp-bci || true
}

@test "Unauthorized access should fail" {
  run ../test-client list --endpoint "$MCP_URL" --skip-tls-verify
  [ "$status" -ne 0 ]
  [[ "$output" == *"401"* ]] || [[ "$output" == *"403"* ]] || [[ "$output" == *"unauthorized"* ]] || [[ "$output" == *"Forbidden"* ]] || [[ "$output" == *"EOF"* ]] || [[ "$output" == *"Failed to connect"* ]]
}

@test "Get token for mcp-user and list units" {
  # Get token
  TOKEN=$(curl -s -X POST "$TOKEN_URL" \
    -d "client_id=systemd-mcp" \
    -d "username=mcp-user" \
    -d "password=user123" \
    -d "grant_type=password" \
    -d "scope=openid systemd-audience mcp:read" | grep -Po '"access_token":\s*"\K[^"]*')
  
  [ -n "$TOKEN" ]
  
  # List units via MCP
  run ../test-client run list_loaded_units -a '{"patterns":["dummy.service"]}' --endpoint "$MCP_URL" --token "$TOKEN" --skip-tls-verify
    
  [ "$status" -eq 0 ]
  [[ "$output" == *"dummy.service"* ]]
}

@test "mcp-user should not be able to restart dummy service" {
  TOKEN=$(curl -s -X POST "$TOKEN_URL" \
    -d "client_id=systemd-mcp" \
    -d "username=mcp-user" \
    -d "password=user123" \
    -d "grant_type=password" \
    -d "scope=openid systemd-audience mcp:read mcp:write" | grep -Po '"access_token":\s*"\K[^"]*')
  
  run ../test-client run change_unit_state -a '{"name":"dummy.service","action":"restart"}' --endpoint "$MCP_URL" --token "$TOKEN" --skip-tls-verify
    
  [ "$status" -eq 0 ]
  [[ "$output" == *"wasn't authorized"* ]] || [[ "$output" == *"Authorization denied"* ]] || [[ "$output" == *"Tool returned an error"* ]]
}

@test "mcp-admin should be able to restart dummy service" {
  TOKEN=$(curl -s -X POST "$TOKEN_URL" \
    -d "client_id=systemd-mcp" \
    -d "username=mcp-admin" \
    -d "password=admin123" \
    -d "grant_type=password" \
    -d "scope=openid systemd-audience mcp:read mcp:write" | grep -Po '"access_token":\s*"\K[^"]*')
  
  run ../test-client run change_unit_state -a '{"name":"dummy.service","action":"restart"}' --endpoint "$MCP_URL" --token "$TOKEN" --skip-tls-verify
    
  [ "$status" -eq 0 ]
  # Check for success indicators in the MCP response
  [[ "$output" == *"Finished"* ]] || [[ "$output" == *"progress"* ]] || [[ "$output" == *"active"* ]]
}
