# Model Context Protocol (MCP) for systemd

![Test Status](https://github.com/mslacken/systemd-mcp/actions/workflows/test.yml/badge.svg)
![Build Status](https://github.com/mslacken/systemd-mcp/actions/workflows/build.yml/badge.svg)
![Release Status](https://github.com/mslacken/systemd-mcp/actions/workflows/release.yml/badge.svg)

The server directly connects to systemd via its C API and so doesn't need systemctl to run.

# Installation

Compile directly with
```bash
  go build -o bin/systemd-mcp .
  go build -o bin/gatekeeper ./gatekeeper
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

    If the system D-Bus is not available (e.g. a container without systemd), `systemd-mcp` starts up in an unauthenticated fallback mode instead of exiting: reads are always allowed and write operations are not gated by polkit. Local tools then report that the local system bus is unavailable, while remote hosts registered via `set_host` remain fully operable.

## Remote Hosts (SSH)

Operations on a remote host registered with `set_host` are not authorized via polkit or the `gatekeeper` on that host. They run with the privileges of the SSH user on the remote host, so the scope of access is defined by the remote user account (and the polkit rules of the remote host for D-Bus calls made by that user).

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
| `--timeout`         |           | Set the timeout for authentication in seconds.                                                          | `5`     |
| `--noauth`          |           | Disable authorization. Must be set to `ThisIsInsecure`. Mutually exclusive with `--controller`.           | `""`    |
| `--toon`            |           | Use token optimized object notation for tool output.                                                      | `false` |
| `--cert-file`       |           | Path to server certificate file (PEM format) for TLS. Requires `--key-file`.                            | `""`    |
| `--key-file`        |           | Path to server private key file (PEM format) for TLS. Requires `--cert-file`.                           | `""`    |
| `--remote-hosts`    |           | Preconfigure a remote host as `name:target[,user=U][,key_file=K][,known_hosts=F][,insecure][,remote_cmd=C]`. Repeatable. | `[]` |
| `--version`         |           | Print the version and exit.                                                                             | `false` |

## Required Flag Combinations

*   **HTTP Mode**: Requires either `--controller` OR `--noauth=ThisIsInsecure`.
*   **TLS**: Both `--cert-file` and `--key-file` must be provided together.
*   **Authentication**: `--noauth` and `--controller` are mutually exclusive.

# Functionality

All tools except `get_man_page` accept a `host` argument that selects the endpoint the command runs on: `localhost` (or empty), a synonym for the local machine (`os.Hostname()`), or a remote host that has been registered with `set_host`. Every result carries a `host` field naming the machine it refers to.

Following tools are provided:
* `set_host`: Manage hosts — `register` a remote host (SSH target + auth), `unregister` a remote host, and `list` the known hosts. The local host is always available as `localhost`.
* `list_loaded_units`: List systemd units that are currently loaded in memory. Filter by states (e.g. `running`, `failed`) or patterns. Can return detailed properties.
* `list_unit_files`: List all systemd unit files on disk. Filter by enablement states (e.g. `enabled`, `disabled`) or patterns.
* `change_unit_state`: Change the state of a unit or service (start, stop, restart, reload, enable, disable).
* `check_restart_reload`: Check the reload or restart status of a unit. Can only be called if the restart or reload job timed out.
* `list_log`: Get the last log entries for the given service or unit. The `from`/`to` fields accept an RFC3339 timestamp, `'now'`, or a duration offset from now such as `'6h'`, `'1d'`, `'90m'`, `'-1d'` (that much **before** now) or `'+1d'` (that much **after** now). Allowed units are `ms`, `s`, `m`, `h`, `d`, `w`, `y`; `ms` is the finest resolution. On a remote host the log is read by running `journalctl` over SSH.
* `get_file`: Read a file or list a directory. Can show content and metadata. Supports pagination for large files. On a remote host the file is read by running `stat`, `find` and `cat` over SSH.
* `get_man_page`: Retrieve a man page from the local system. Supports filtering by section and chapters, and pagination.

## Remote Hosts

Remote hosts use the same mechanism `systemctl -H`/`busctl -H` use: each D-Bus connection is an SSH session running `systemd-stdio-bridge` on the remote host, so the D-Bus bytes ride a single SSH channel and no additional daemon or open port is needed there.

Requirements on the remote host:
*   An SSH server and `systemd-stdio-bridge` in `PATH` (ships with systemd; override with `remote_cmd`).
*   `journalctl` for `list_log`, and `stat`, `find` and `cat` for `get_file`.

SSH authentication:
*   The user defaults to `$USER`.
*   Keys from the local ssh-agent, a `key_file`, and the default keys `~/.ssh/id_ed25519` and `~/.ssh/id_rsa` are tried; a `password` can be given as an alternative. Passwords are never included in `list` output.

Host-key verification:
*   Host keys are checked against `known_hosts` (default `~/.ssh/known_hosts` if it exists).
*   An unknown host key is shown to the user via an MCP elicitation, who can accept it (trusted for the lifetime of the server process) or reject it (the connection is refused).
*   `insecure` accepts any host key and is meant for testing only.

On registration a connection is established right away, so an unreachable host or a rejected host key makes the registration fail. The host's `/etc/hostname` is read to name the host if no name, or a generic placeholder (`localhost`, `linux`, ...) was given; otherwise a unique name is derived from the target. The host's `/etc/os-release` is read as well, so `list` reports the operating system of every registered host.

Remote hosts can be registered at runtime with `set_host`, or preconfigured at startup:

```
systemd-mcp \
  --remote-hosts 'web1:10.0.0.5,user=admin,key_file=~/.ssh/id_ed25519' \
  --remote-hosts 'db1:10.0.0.7:2222,known_hosts=~/.ssh/known_hosts'
```

For debugging the SSH/D-Bus transport without an MCP client, a small standalone tool is provided:

```bash
  go build -o bin/systemd-ssh-demo ./cmd/systemd-ssh-demo
  bin/systemd-ssh-demo -target user@host:22 status systemd-journald
```

# Testing

For testing purposes the test client `./testClient/main.go` is provided, build it with `make test-client`.
Run the unit tests with `make test`. `systemd-mcp_test.go` tests authentication with oauth2 using a keycloak container, and `test/` contains bats based integration tests.

The journal tests run against the synthetic journal file `internal/pkg/journal/testdata/test.journal`, which has deterministic content and contains no data of a real host. It can be regenerated with `internal/pkg/journal/testdata/make-test-journal.sh`, which requires `systemd-journal-remote`.

