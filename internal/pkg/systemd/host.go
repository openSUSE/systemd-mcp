package systemd

import (
	"encoding/json"

	"github.com/openSUSE/systemd-mcp/internal/pkg/util"
)

// LocalHost is the host name that addresses this machine's own D-Bus system
// bus. It is a synonym for "localhost" and always works without any
// registration.
const LocalHost = "localhost"

// HostInfo describes a single systemd bus endpoint the MCP tools can operate
// against. It is the concrete form of the "host" parameter: it names the host
// and, for remote hosts, everything needed to reach its D-Bus system bus over
// SSH — the same mechanism systemctl -H / busctl -H use.
//
// A local host (LocalHost) uses this machine's own system bus. Any other host
// is reached over SSH: for every D-Bus connection an SSH session channel is
// opened on Target and RemoteCmd (default "systemd-stdio-bridge") is exec'd in
// it, and the D-Bus bytes ride that single channel — no socat / TCP bridge on
// the remote host.
type HostInfo struct {
	// Name is the identifier clients pass as the "host" argument.
	Name string `json:"name" jsonschema:"Identifier of the host; use 'localhost' for the local bus."`

	Target     string `json:"target,omitempty" jsonschema:"SSH target host[:port] (default port 22). Required for remote hosts."`
	User       string `json:"user,omitempty" jsonschema:"SSH user (defaults to the $USER environment variable)." `
	KeyFile    string `json:"key_file,omitempty" jsonschema:"Path to an SSH private key file (the local ssh-agent is also consulted)." `
	Password   string `json:"-" jsonschema:"SSH password (used when no key/agent auth is available). Intentionally omitted from list output."`
	KnownHosts string `json:"known_hosts,omitempty" jsonschema:"Path to a known_hosts file (or ~/.ssh/known_hosts) for host-key verification."`
	Insecure   bool   `json:"insecure,omitempty" jsonschema:"Accept any SSH host key (testing only)."`
	RemoteCmd  string `json:"remote_cmd,omitempty" jsonschema:"Command to run on the remote host (default 'systemd-stdio-bridge')." `
}

// IsLocal reports whether h addresses this machine's own bus.
func (h HostInfo) IsLocal() bool {
	return h.Name == "" || h.Name == LocalHost
}

// SetHostParams drives the set_host tool. Action selects the operation:
// "register" adds a host (using the SSH fields), "unregister" removes a
// remote host, and "list" reports the known hosts.
type SetHostParams struct {
	Action string `json:"action" jsonschema:"One of 'register', 'unregister', 'list'."`
	Host   string `json:"host,omitempty" jsonschema:"Host name to act on (the host argument the other tools use; 'localhost' is the local bus)." `

	// SSH details, used when Action is "register".
	Target     string `json:"target,omitempty" jsonschema:"SSH target host[:port] (default port 22); required for remote registration."`
	User       string `json:"user,omitempty" jsonschema:"SSH user (defaults to $USER)."`
	KeyFile    string `json:"key_file,omitempty" jsonschema:"Path to an SSH private key file (ssh-agent is also consulted)."`
	Password   string `json:"password,omitempty" jsonschema:"SSH password (optional; an alternative to key/agent auth)." `
	KnownHosts string `json:"known_hosts,omitempty" jsonschema:"Path to a known_hosts file for host-key verification."`
	Insecure   bool   `json:"insecure,omitempty" jsonschema:"Accept any SSH host key (testing only)."`
	RemoteCmd  string `json:"remote_cmd,omitempty" jsonschema:"Command to run on the remote host (default 'systemd-stdio-bridge')."`
}

// effectiveHost maps a requested host argument to the name its endpoint is
// reported under: the local machine's real hostname for the local bus, and the
// host's own name for remote hosts.
func effectiveHost(host string) string {
	if host == "" || host == LocalHost {
		return util.LocalHostName()
	}
	return host
}

// EncodeWithHost encodes value alongside a top-level "host" field naming the
// bus endpoint (host) it was produced on. value is normalised to a JSON object
// first (the same shape the toon encoder produces), so json and toon agree.
func EncodeWithHost(enc util.OutputEncoding, host string, value any) ([]byte, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	m["host"] = effectiveHost(host)
	return enc.Encode(m)
}

// hostMessage wraps a plain status message with the host it was produced on, so
// even terse results keep the host they came from.
func hostMessage(host, message string) string {
	b, err := json.Marshal(map[string]any{
		"host":    effectiveHost(host),
		"message": message,
	})
	if err != nil {
		return `{"host":"localhost","message":"` + message + `"}`
	}
	return string(b)
}

// hostOnly returns a payload with just the host, for calls that produce no
// other data.
func hostOnly(host string) string {
	b, err := json.Marshal(map[string]any{"host": effectiveHost(host)})
	if err != nil {
		return `{"host":"localhost"}`
	}
	return string(b)
}
