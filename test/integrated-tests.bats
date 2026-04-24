#!/usr/bin/bats
TEST_CONTAINER=${TEST_CONTAINER:-bci-init-build.docker}
TEST_BINARY=${TEST_BINARY:-systemd-mcp}

setup_file() {
  export INIT_PAYLOAD='{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {
      "name": "test",
      "version": "1.0"
    }
  }
}
{"jsonrpc":"2.0","method":"notifications/initialized"}'
  export CONTAINER_NAME="systemd-mcp-test-$(date +%s)-$RANDOM"
  cd ${BATS_TEST_DIRNAME}/../
  make dist
  cp systemd-mcp.tar.gz ${BATS_TEST_DIRNAME}
  cd ${BATS_TEST_DIRNAME}
  podman build -t systemd-mcp-bci -f $TEST_CONTAINER .
  
  podman run -d --name $CONTAINER_NAME --privileged systemd-mcp-bci
  
  for i in {1..30}; do
    if podman exec $CONTAINER_NAME systemctl is-system-running | grep -qE "running|degraded"; then
      echo "# systemd is ready" >&3
      return 0
    fi
    sleep 1
  done
  return 1
}

teardown_file() {
  podman rm -f $CONTAINER_NAME || true
  podman image rm systemd-mcp-bci || true
  rm -f ${BATS_TEST_DIRNAME}/systemd-mcp.tar.gz
}

@test "Run systemd-mcp --noauth without parameter must fail" {
  run podman run --entrypoint $TEST_BINARY systemd-mcp-bci --noauth
  [ "$status" -ne 0 ]
}

@test "check unit state of dummy.service which needs to succeed" {
  # We use the correct noauth parameter here to ensure it succeeds
  # Note: (cat <<EOF ... EOF; sleep 1) is needed to keep stdin open long enough for the server to process and flush output
  run bash -c "(echo -e \"\$INIT_PAYLOAD\"; cat <<'EOF'
{
  \"jsonrpc\": \"2.0\",
  \"id\": 2,
  \"method\": \"tools/call\",
  \"params\": {
    \"name\": \"list_loaded_units\",
    \"arguments\": {
      \"patterns\": [\"dummy.service\"]
    }
  }
}
EOF
sleep 1) | podman exec -i $CONTAINER_NAME $TEST_BINARY --noauth ThisIsInsecure"
  [ "$status" -eq 0 ]
  [[ "$output" == *"dummy.service"* ]]
  [[ "$output" == *"running"* ]] || [[ "$output" == *"active"* ]]
}

@test "check for failed units" {
  # We use the correct noauth parameter here to ensure it succeeds
  # Note: (cat <<EOF ... EOF; sleep 1) is needed to keep stdin open long enough for the server to process and flush output
  run bash -c "(echo -e \"\$INIT_PAYLOAD\"; cat <<'EOF'
{
  \"jsonrpc\": \"2.0\",
  \"id\": 2,
  \"method\": \"tools/call\",
  \"params\": {
    \"name\": \"list_loaded_units\",
    \"arguments\": {
      \"state\": \"failed\"
    }
  }
}
EOF
sleep 1) | podman exec -i $CONTAINER_NAME $TEST_BINARY --noauth ThisIsInsecure"
  [ "$status" -eq 0 ]
  [[ "$output" == *"failed-dummy.service"* ]]
  [[ "$output" == *"failed"* ]]
}

@test "check list_loaded_units rejects invalid state" {
  run bash -c "(echo -e \"\$INIT_PAYLOAD\"; cat <<'EOF'
{
  \"jsonrpc\": \"2.0\",
  \"id\": 2,
  \"method\": \"tools/call\",
  \"params\": {
    \"name\": \"list_loaded_units\",
    \"arguments\": {
      \"state\": \"invalid_made_up_state\"
    }
  }
}
EOF
sleep 1) | podman exec -i $CONTAINER_NAME $TEST_BINARY --noauth ThisIsInsecure"
  
  # When arguments violate JSON schema in MCP, the standard Go SDK implementation returns an error response
  # Note: It might return exit 0 for the process but contain an error in the JSON response
  [[ "$output" == *"error"* ]] || [[ "$output" == *"invalid"* ]]
}


@test "check list_unit_files for dummy.service" {
  run bash -c "(echo -e \"\$INIT_PAYLOAD\"; cat <<'EOF'
{
  \"jsonrpc\": \"2.0\",
  \"id\": 2,
  \"method\": \"tools/call\",
  \"params\": {
    \"name\": \"list_unit_files\",
    \"arguments\": {
      \"patterns\": [\"dummy.service\"]
    }
  }
}
EOF
sleep 1) | podman exec -i $CONTAINER_NAME $TEST_BINARY --noauth ThisIsInsecure"
  [ "$status" -eq 0 ]
  [[ "$output" == *"dummy.service"* ]]
  [[ "$output" == *"enabled"* ]] || [[ "$output" == *"disabled"* ]] || [[ "$output" == *"static"* ]]
}

@test "check input schema for list_loaded_units" {
  run bash -c "(echo -e \"\$INIT_PAYLOAD\"; cat <<'EOF'
{
  \"jsonrpc\": \"2.0\",
  \"id\": 2,
  \"method\": \"tools/list\"
}
EOF
sleep 1) | podman exec -i $CONTAINER_NAME $TEST_BINARY --noauth ThisIsInsecure"
  [ "$status" -eq 0 ]
  # Check if tool list_loaded_units exists and has correct schema parts
  [[ "$output" == *"list_loaded_units"* ]]
  [[ "$output" == *"\"state\""* ]]
  [[ "$output" == *"\"patterns\""* ]]
  [[ "$output" == *"\"properties\""* ]]
  [[ "$output" == *"\"verbose\""* ]]
  # Check for some valid states in enum (SubStates like 'running' are no longer supported)
  [[ "$output" == *"active"* ]]
  [[ "$output" == *"all"* ]]
  [[ "$output" == *"failed"* ]]
}

@test "check input schema for list_unit_files" {
  run bash -c "(echo -e \"\$INIT_PAYLOAD\"; cat <<'EOF'
{
  \"jsonrpc\": \"2.0\",
  \"id\": 2,
  \"method\": \"tools/list\"
}
EOF
sleep 1) | podman exec -i $CONTAINER_NAME $TEST_BINARY --noauth ThisIsInsecure"
  [ "$status" -eq 0 ]
  # Check if tool list_unit_files exists and has correct schema parts
  [[ "$output" == *"list_unit_files"* ]]
  [[ "$output" == *"\"state\""* ]]
  [[ "$output" == *"\"patterns\""* ]]
  # Check for some valid enablement states in enum
  [[ "$output" == *"enabled"* ]]
  [[ "$output" == *"disabled"* ]]
  [[ "$output" == *"masked"* ]]
}


@test "restart the dummy unit which must fail as user isn't allowed and testuser can't do it" {
  run bash -c "(echo -e \"\$INIT_PAYLOAD\"; cat <<'EOF'
{
  \"jsonrpc\": \"2.0\",
  \"id\": 2,
  \"method\": \"tools/call\",
  \"params\": {
    \"name\": \"change_unit_state\",
    \"arguments\": {
      \"name\": \"dummy.service\",
      \"action\": \"restart\"
    }
  }
}
EOF
sleep 1) | podman exec -i --user testuser $CONTAINER_NAME $TEST_BINARY"
  # The exit status might be 0 because the server ran, but the MCP response should be an error
  [[ "$output" == *"wasn't authorized"* ]] || [[ "$output" == *"Authorization denied"* ]] || [[ "$output" == *"authorized externally"* ]]
}

@test "restart the dummy with the correct noauth parameter what also must suceed" {
  run bash -c "(echo -e \"\$INIT_PAYLOAD\"; cat <<'EOF'
{
  \"jsonrpc\": \"2.0\",
  \"id\": 2,
  \"method\": \"tools/call\",
  \"params\": {
    \"name\": \"change_unit_state\",
    \"arguments\": {
      \"name\": \"dummy.service\",
      \"action\": \"restart\"
    }
  }
}
EOF
sleep 1) | podman exec -i $CONTAINER_NAME $TEST_BINARY --noauth ThisIsInsecure"
  [ "$status" -eq 0 ]
  # The output should contain something indicating success
  # For restart, it might return \"Finished\" or similar from CheckForRestartReloadRunning
  [[ "$output" == *"Finished"* ]] || [[ "$output" == *"progress"* ]]
}

@test "check log entries of dummy.service using list_log with regexp" {
  run bash -c "(echo -e \"\$INIT_PAYLOAD\"; cat <<'EOF'
{
  \"jsonrpc\": \"2.0\",
  \"id\": 2,
  \"method\": \"tools/call\",
  \"params\": {
    \"name\": \"list_log\",
    \"arguments\": {
      \"unit\": [\"dum.*\\\\.service\"],
      \"exact_unit\": false,
      \"count\": 10
    }
  }
}
EOF
sleep 1) | podman exec -i $CONTAINER_NAME $TEST_BINARY --noauth ThisIsInsecure"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Dummy log line at"* ]]
}

@test "check log entries of dummy.service using list_log as loguser with noauth" {
  run bash -c "(echo -e \"\$INIT_PAYLOAD\"; cat <<'EOF'
{
  \"jsonrpc\": \"2.0\",
  \"id\": 2,
  \"method\": \"tools/call\",
  \"params\": {
    \"name\": \"list_log\",
    \"arguments\": {
      \"unit\": [\"dum.*\\\\.service\"],
      \"exact_unit\": false,
      \"count\": 10
    }
  }
}
EOF
sleep 1) | podman exec -i --user loguser $CONTAINER_NAME $TEST_BINARY --noauth ThisIsInsecure"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Dummy log line at"* ]]
}
@test "check log entries of dummy.service using list_log as loguser without noauth" {
  run bash -c "(echo -e \"\$INIT_PAYLOAD\"; cat <<'EOF'
{
  \"jsonrpc\": \"2.0\",
  \"id\": 2,
  \"method\": \"tools/call\",
  \"params\": {
    \"name\": \"list_log\",
    \"arguments\": {
      \"unit\": [\"dum.*\\\\.service\"],
      \"exact_unit\": false,
      \"count\": 10
    }
  }
}
EOF
sleep 1) | podman exec -i --user loguser $CONTAINER_NAME $TEST_BINARY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Dummy log line at"* ]]
}
