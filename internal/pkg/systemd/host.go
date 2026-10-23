package systemd

import (
	"encoding/json"
	"strings"

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

	Target     string `json:"target,omitempty" jsonschema:"SSH target host[:port] (default port 22)."`
	User       string `json:"user,omitempty" jsonschema:"SSH user (defaults to the $USER environment variable)."`
	KeyFile    string `json:"key_file,omitempty" jsonschema:"Path to an SSH private key file (the local ssh-agent is also consulted)."`
	Password   string `json:"-" jsonschema:"SSH password (used when no key/agent auth is available). Intentionally omitted from list output."`
	KnownHosts string `json:"known_hosts,omitempty" jsonschema:"Path to a known_hosts file (or ~/.ssh/known_hosts) for host-key verification."`
	Insecure   bool   `json:"insecure,omitempty" jsonschema:"Whether the host accepts any SSH host key without verification (testing only)."`
	RemoteCmd  string `json:"remote_cmd,omitempty" jsonschema:"Command run on the remote host (defaults to 'systemd-stdio-bridge')."`

	// OS is the underlying OS of the host, captured best-effort from the
	// host's own /etc/os-release at registration time. It is empty when it
	// could not be read (e.g. no /etc/os-release, or the host was never
	// actually connected to).
	OS OSRelease `json:"os,omitempty" jsonschema:"The underlying operating system of this host, read from its /etc/os-release at registration time (empty when unknown)." `
}

// OSRelease is the subset of the remote host's /etc/os-release this server
// cares about, captured best-effort at registration time so an MCP response can
// report the underlying OS.
type OSRelease struct {
	Name        string `json:"name,omitempty"`
	Variant     string `json:"variant,omitempty"`
	Version     string `json:"version,omitempty"`
	ID          string `json:"id,omitempty"`
	IDLike      string `json:"id_like,omitempty"`
	VersionID   string `json:"version_id,omitempty"`
	PrettyName  string `json:"pretty_name,omitempty"`
	ANSIColor   string `json:"ansi_color,omitempty"`
	ANSIIconName string `json:"ansi_icon_name,omitempty"`
}

// String renders a short human/LLM readable label such as
// "openSUSE Leap 15.6" (Name + Version) or, lacking that, the ID. It returns
// "" when nothing usable was captured.
func (o OSRelease) String() string {
	if o.Name != "" && o.Version != "" {
		return o.Name + " " + o.Version
	}
	if o.PrettyName != "" {
		return o.PrettyName
	}
	if o.Name != "" {
		return o.Name
	}
	return o.ID
}

// IsLocal reports whether h addresses this machine's own bus.
func (h HostInfo) IsLocal() bool {
	return h.Name == "" || h.Name == LocalHost
}

// parseOSRelease parses the KEY=VALUE lines of /etc/os-release into an
// OSRelease. Lines that are not valid KEY=VALUE (comments, blank, malformed)
// are ignored, so a partial or nonstandard file still yields the fields we
// captured.
func parseOSRelease(content string) OSRelease {
	var rel OSRelease
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimRight(raw, "\r")
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := line[:eq]
		val := unquoteOSRelease(line[eq+1:])
		switch key {
		case "NAME":
			rel.Name = val
		case "VARIANT":
			rel.Variant = val
		case "VERSION":
			rel.Version = val
		case "ID":
			rel.ID = val
		case "ID_LIKE":
			rel.IDLike = val
		case "VERSION_ID":
			rel.VersionID = val
		case "PRETTY_NAME":
			rel.PrettyName = val
		case "ANSI_COLOR":
			rel.ANSIColor = val
		case "ANSI_ICON_NAME":
			rel.ANSIIconName = val
		}
	}
	return rel
}

// unquoteOSRelease strips the matching surrounding single or double quotes of a
// value and, for double-quoted values, expands the minimal escape set
// (\\" \\\\ and \\n) so it matches the value /etc/os-release intends.
func unquoteOSRelease(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if s[0] == '\'' && s[len(s)-1] == '\'' {
			return s[1 : len(s)-1]
		}
		if s[0] == '"' && s[len(s)-1] == '"' {
			s = s[1 : len(s)-1]
			var b strings.Builder
			for i := 0; i < len(s); i++ {
				c := s[i]
				if c == '\\' && i+1 < len(s) {
					switch s[i+1] {
					case '"':
						b.WriteByte('"')
						i++
						continue
					case '\\':
						b.WriteByte('\\')
						i++
						continue
					case 'n':
						b.WriteByte('\n')
						i++
						continue
					}
				}
				b.WriteByte(c)
			}
			return b.String()
		}
	}
	return s
}

// SetHostParams drives the set_host tool. Action selects the operation:
// "register" adds a host (using the SSH fields), "unregister" removes a
// remote host, and "list" reports the known hosts.
type SetHostParams struct {
	Action string `json:"action" jsonschema:"Required. Operation to perform. 'register' adds a remote host (needs host, target and SSH auth); 'unregister' removes one (needs host); 'list' reports the known hosts (needs nothing). Defaults to 'list'."`
	Host   string `json:"host,omitempty" jsonschema:"Host name to act on (the identifier the other tools use for this bus). Required for 'register' (it must not be 'localhost') and for 'unregister'; ignored for 'list'."`

	// SSH details, used when Action is "register".
	Target     string `json:"target,omitempty" jsonschema:"SSH target host[:port] (default port 22). Required for 'register'; ignored by 'unregister' and 'list'."`
	User       string `json:"user,omitempty" jsonschema:"SSH user. Optional; defaults to $USER."`
	KeyFile    string `json:"key_file,omitempty" jsonschema:"Path to an SSH private key file. Optional; the local ssh-agent is also consulted, together with common default key files (~/.ssh/id_ed25519, ~/.ssh/id_rsa)." `
	Password   string `json:"password,omitempty" jsonschema:"SSH password. Optional; an alternative to key/agent auth." `
	KnownHosts string `json:"known_hosts,omitempty" jsonschema:"Path to a known_hosts file for host-key verification. Optional; defaults to ~/.ssh/known_hosts when it exists. A key that is neither trusted nor in known_hosts is shown to the user, who may then choose to accept (trust it for this host) or ignore (refuse the connection) it."`
	Insecure   bool   `json:"insecure,omitempty" jsonschema:"Accept any SSH host key without verification. Optional (testing only); defaults to false."`
	RemoteCmd  string `json:"remote_cmd,omitempty" jsonschema:"Command to run on the remote host. Optional; defaults to 'systemd-stdio-bridge'."`
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
