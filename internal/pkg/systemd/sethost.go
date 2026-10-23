package systemd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const setHostDescription = `Manage the bus hosts the other tools can operate on.
Actions (the 'action' parameter, required, defaults to 'list'):
  - 'register'   adds a remote host. Required: 'host' (a name that is NOT 'localhost') and 'target' (the SSH host[:port]); at least one form of SSH authentication must already be available (ssh-agent, key_file, or password). Optional: user, key_file, password, known_hosts, insecure, remote_cmd.
  - 'unregister' removes a remote host. Required: 'host'. Any other parameter is ignored and any previously accepted host key for this host is cleared.
  - 'list'       reports the known hosts. Nothing else is required.
'register' is equivalent to establishing an SSH connection to that host: the tools reach its D-Bus system bus over SSH from then on (think 'ssh user@host'). The local host is always available as 'localhost' and needs no registration.
Host-key handling: on the first connection to a remote host, if its SSH host key is neither in known_hosts nor already trusted, it is shown to the user, who may accept it (trusted for this server run) or ignore it (the connection is refused).`

// SetHostDescription is the human/tool description for the set_host tool.
func SetHostDescription() string {
	return setHostDescription
}

// CreateSetHostSchema builds the input schema for the set_host tool.
func CreateSetHostSchema() *jsonschema.Schema {
	schema, _ := jsonschema.For[SetHostParams](nil)
	if p := schema.Properties["action"]; p != nil {
		p.Enum = []any{"register", "unregister", "list"}
		p.Default = json.RawMessage(`"list"`)
	}
	return schema
}

// SetHost implements the set_host tool: register / unregister / list.
func (conn *Connection) SetHost(ctx context.Context, req *mcp.CallToolRequest, params *SetHostParams) (*mcp.CallToolResult, any, error) {
	slog.Debug("SetHost called", "params", params)
	if allowed, err := conn.auth.IsReadAuthorized(ctx); err != nil {
		return nil, nil, err
	} else if !allowed {
		return nil, nil, fmt.Errorf("calling method was canceled by user")
	}
	if conn.reg == nil {
		return nil, nil, fmt.Errorf("host registry is unavailable")
	}

	switch params.Action {
	case "register":
		if params.Host == "" || params.Host == LocalHost {
			return nil, nil, fmt.Errorf("register: refusing to register the local host; it is always available as 'localhost'")
		}
		if params.Target == "" {
			return nil, nil, fmt.Errorf("register: target (ssh host[:port]) is required for a remote host")
		}
		info := HostInfo{
			Name:       params.Host,
			Target:     params.Target,
			User:       params.User,
			KeyFile:    params.KeyFile,
			Password:   params.Password,
			KnownHosts: params.KnownHosts,
			Insecure:   params.Insecure,
			RemoteCmd:  params.RemoteCmd,
		}
		// Establish a real connection now (SSH auth, host-key check, D-Bus
		// handshake) so a reachable host is confirmed and an untrusted host key
		// is elicited from the user at registration time. The host is stored
		// only if this succeeds, so a failed registration drops an error.
		verify := conn.verifyConnect
		if verify == nil {
			verify = conn.verifyHostConnect
		}
		var session *mcp.ServerSession
		if req != nil {
			session = req.Session
		}
		if err := verify(ctx, info, session); err != nil {
			return nil, nil, fmt.Errorf("register: host %q is not usable: %w", params.Host, err)
		}
		// Best-effort: read the host's /etc/os-release over the same trusted
		// connection so the registration (and `list` output afterwards) carries
		// the underlying OS. Failure is logged, never fatal — the OS is simply
		// left empty.
		if fetch := conn.fetchOSRelease; fetch != nil {
			if raw, err := fetch(ctx, req, info); err == nil {
				info.OS = parseOSRelease(raw)
			} else {
				slog.Debug("couldn't read remote /etc/os-release; continuing without OS",
					"host", params.Host, slog.Any("error", err))
			}
		}
		conn.reg.Register(info)
		slog.Debug("registered remote host", "host", params.Host, "target", params.Target, "os", info.OS.String())
		msg := fmt.Sprintf("registered host %q", params.Host)
		if o := info.OS.String(); o != "" {
			msg += fmt.Sprintf(" (OS: %s)", o)
		}
		return hostResult(msg)
	case "unregister":
		if err := conn.reg.Unregister(params.Host); err != nil {
			return nil, nil, err
		}
		return hostResult(fmt.Sprintf("unregistered host %q", params.Host))
	case "list", "":
		list := conn.reg.List()
		payload := struct {
			Host  string     `json:"host"`
			Hosts []HostInfo `json:"hosts"`
		}{Host: effectiveHost(LocalHost), Hosts: list}
		b, err := EncodeWithHost(conn.Encoder, LocalHost, &payload)
		if err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: string(b)},
			},
		}, nil, nil
	default:
		return nil, nil, fmt.Errorf("unknown action %q (want register, unregister, or list)", params.Action)
	}
}

// hostResult returns a single text result carrying host and message.
func hostResult(message string) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: hostMessage(LocalHost, message)},
		},
	}, nil, nil
}
