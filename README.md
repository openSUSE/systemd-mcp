# Model Context Protocol (MCP) for systemd

![Test Status](https://github.com/mslacken/systemd-mcp/actions/workflows/test.yml/badge.svg)
![Build Status](https://github.com/mslacken/systemd-mcp/actions/workflows/build.yml/badge.svg)
![Release Status](https://github.com/mslacken/systemd-mcp/actions/workflows/release.yml/badge.svg)

The server directly connects to systemd via its C API and so doesn't need systemctl to run.

# Installation

Compile directly with
```bash
  go build -o bin/systemd-mcp systemd-mcp.go
  go build -o bin/gatekeeper gatekeeper/main.go
```
or use the provided Makefile:
```bash
  make build
```
and install with
```bash
  sudo make install
```

The `make install` command installs:
*   `systemd-mcp` to `/usr/bin/systemd-mcp`
*   `gatekeeper` to `/usr/sbin/gatekeeper`
*   Systemd units for `gatekeeper.service` and `gatekeeper.socket`
*   Polkit policy for `gatekeeper`

# Security

## Stdio Transport (Polkit/DBus)

When running over Stdio (default), `systemd-mcp` uses `polkit` for authorization. The process runs as the current user.

*   **Unit Management**: Operations like starting or stopping units trigger a polkit request for `org.freedesktop.systemd1.manage-units`.
*   **Log Access**: `systemd-mcp` tries to open the whole journal in this order:
    *   If running as root or in the same group as the directory `/var/log/journal`, all journal files are accessible.
    *   Else `systemd-mcp` connects to the `gatekeeper` via `/run/gatekeeper/gatekeeper.socket`. This triggers a polkit request for `com.suse.gatekeeper.readlog`.
    *   If the gatekeeper isn't usable, only the journal files readable by the current user (e.g. its own `user-<uid>.journal` files) are used. The log output contains a hint about this reduced access.

    Read operations over the stdio transport are always authorized, as the calling user runs the server itself; only write operations still trigger a polkit request.

## HTTP Transport (OAuth2)

When running over HTTP (using `--http`), `systemd-mcp` uses OAuth2 for authorization.
You must specify an OAuth2 controller address using `--controller`.

*   **OAuth2 Configuration**:
    *   **Audience**: `systemd-mcp-server`
    *   **Supported Scopes**:
        *   `mcp:read`: Allows read-only access (e.g., listing units, reading logs).
        *   `mcp:write`: Allows write access (e.g., starting/stopping units).

If the HTTP server is started as `root` or in the journal group, it accesses the whole journal directly. Otherwise the `gatekeeper` is used for log access, provided `gatekeeper.socket` is available; if it isn't, only the journal files readable by the current user are shown.

## HTTP Transport with authentication

For debugging purposes, the `--noauth` flag can be used to access the MCP server without authentication. To ensure this is intentional, the flag must be set exactly to `ThisIsInsecure`.

### Self-signed certificates

To run the server in HTTP mode with TLS, you need a certificate and a key. You can generate self-signed certificates for local testing with:

```bash
  make certs
```

# Command-line Options

| Flag                | Shorthand | Description                                                                                             | Default |
|---------------------|-----------|---------------------------------------------------------------------------------------------------------|---------|
| `--http`            |           | If set, use streamable HTTP at this address, instead of stdin/stdout.                                   | `""`    |
| `--skip-tls-verify` |           | Skip TLS certificate verification for outbound requests (e.g. to OAuth2 controller).                    | `false` |
| `--controller`      |           | OAuth2 controller address (required for HTTP mode unless `--noauth` is used).                           | `""`    |
| `--logfile`         |           | If set, log to this file instead of stderr.                                                             | `""`    |
| `--verbose`         | `-v`      | Enable verbose logging.                                                                                 | `false` |
| `--debug`           | `-d`      | Enable debug logging.                                                                                   | `false` |
| `--log-json`        |           | Output logs in JSON format (machine-readable).                                                          | `false` |
| `--list-tools`      |           | List all available tools and exit.                                                                      | `false` |
| `--allow-write`     | `-w`      | Authorize write to systemd.                                                                             | `false` |
| `--allow-read`      | `-r`      | Authorize read to systemd.                                                                              | `false` |
| `--enabled-tools`   |           | A comma-separated list of tools to enable. Defaults to all tools.                                       | all     |
| `--timeout`         |           | Set the timeout for polkit authentication in seconds.                                                   | `5`     |
| `--noauth`          |           | Disable authorization. Must be set to `ThisIsInsecure`. Mutually exclusive with `--controller`.           | `""`    |
| `--toon`            |           | Use token optimized object notation for tool output.                                                      | `false` |
| `--cert-file`       |           | Path to server certificate file (PEM format) for TLS. Requires `--key-file`.                            | `""`    |
| `--key-file`        |           | Path to server private key file (PEM format) for TLS. Requires `--cert-file`.                           | `""`    |
| `--version`         |           | Print the version and exit.                                                                             | `false` |

## Required Flag Combinations

*   **HTTP Mode**: Requires either `--controller` OR `--noauth=ThisIsInsecure`.
*   **TLS**: Both `--cert-file` and `--key-file` must be provided together.
*   **Authentication**: `--noauth` and `--controller` are mutually exclusive.

# Functionality

Every tool accepts a `host` argument that identifies the host on which the command runs. It defaults to `localhost`, which is a synonym for the local machine (`os.Hostname()`); any other value names the target host.

Following tools are provided:
* `list_units`: List systemd units. Filter by states (e.g. `running`, `failed`) or patterns. Can return detailed properties. Use `mode='files'` to list all installed unit files.
* `change_unit_state`: Change the state of a unit or service (start, stop, restart, reload, enable, disable).
* `check_restart_reload`: Check the reload or restart status of a unit. Can only be called if the restart or reload job timed out.
* `list_log`: Get the last log entries for the given service or unit.
* `get_file`: Read a file from the system. Can show content and metadata. Supports pagination for large files.
* `get_man_page`: Retrieve a man page. Supports filtering by section and chapters, and pagination.

# Testing

For testing purposes the test client `./test/main.go` is provided.
Also there are several unit tests including `systemd_test.go` which tests authentication with oauth2 using a keycloak container.

