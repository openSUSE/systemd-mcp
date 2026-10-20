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
Actions: 'register' adds a remote host, 'unregister' removes a remote host, and 'list' reports the known hosts.
'register' is equivalent to establishing an SSH connection to that host: you supply the SSH target (host[:port]) and authentication (user, key_file or password), and the tools reach its D-Bus system bus over SSH from then on (think 'ssh user@host').
The local host is always available as 'localhost' and needs no registration.`

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
func (conn *Connection) SetHost(ctx context.Context, _ *mcp.CallToolRequest, params *SetHostParams) (*mcp.CallToolResult, any, error) {
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
		conn.reg.Register(HostInfo{
			Name:       params.Host,
			Target:     params.Target,
			User:       params.User,
			KeyFile:    params.KeyFile,
			Password:   params.Password,
			KnownHosts: params.KnownHosts,
			Insecure:   params.Insecure,
			RemoteCmd:  params.RemoteCmd,
		})
		slog.Debug("registered remote host", "host", params.Host, "target", params.Target)
		return hostResult(fmt.Sprintf("registered host %q", params.Host))
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
