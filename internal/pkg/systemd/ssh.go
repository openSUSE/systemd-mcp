package systemd

import (
	"context"
	"fmt"
	"net"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/openSUSE/systemd-mcp/internal/pkg/extdbus"
)

// hosts stores the bus endpoints the server can talk to. The local host
// (LocalHost) is always present
type Registry struct {
	entries map[string]HostInfo
}

// NewRegistry creates a registry
func NewRegistry() *Registry {
	return &Registry{entries: map[string]HostInfo{}}
}

// Resolves given string to a concrete HostInfo. Returns an error for
// a remote host if it wasn't registered.
func (r *Registry) Get(name string) (HostInfo, error) {
	name = strings.ToLower(name)
	if name == "" || name == LocalHost {
		return HostInfo{Name: LocalHost}, nil
	}
	info, ok := r.entries[name]
	if !ok {
		return HostInfo{}, fmt.Errorf("host %q is not registered as a remote host; add it with the set_host tool (action='register')", name)
	}
	return info, nil
}

// PreconfigureHosts adds remote hosts supplied at server startup.
// Each entry is:
//
//	name:target[,user=U][,key_file=K][,known_hosts=F][,insecure][,remote_cmd=C]
//
// The name and target are the first comma-separated token (the target may itself
// be host:port); the optional SSH details follow as comma-separated tokens.
// It lets a server be started in a fully remote configuration without the client
// first having to register each host.
func PreconfigureHosts(r *Registry, entries []string) error {
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		segs := strings.Split(entry, ",")
		first := strings.TrimSpace(segs[0])
		ci := strings.IndexByte(first, ':')
		if ci <= 0 {
			return fmt.Errorf("invalid remote host %q (want name:target[,opt...])", raw)
		}
		name := strings.TrimSpace(first[:ci])
		info := HostInfo{Name: name, Target: strings.TrimSpace(first[ci+1:])}
		if info.Target == "" {
			return fmt.Errorf("invalid remote host %q (want name:target[,opt...])", raw)
		}
		for _, tok := range segs[1:] {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			switch {
			case strings.HasPrefix(tok, "user="):
				info.User = strings.TrimSpace(strings.TrimPrefix(tok, "user="))
			case strings.HasPrefix(tok, "key_file="):
				info.KeyFile = strings.TrimSpace(strings.TrimPrefix(tok, "key_file="))
			case strings.HasPrefix(tok, "known_hosts="):
				info.KnownHosts = strings.TrimSpace(strings.TrimPrefix(tok, "known_hosts="))
			case strings.HasPrefix(tok, "remote_cmd="):
				info.RemoteCmd = strings.TrimSpace(strings.TrimPrefix(tok, "remote_cmd="))
			case tok == "insecure":
				info.Insecure = true
			default:
				return fmt.Errorf("unknown option %q for host %q", tok, name)
			}
		}
		r.Register(info)
	}
	return nil
}

// Register adds or replaces a remote host.
func (r *Registry) Register(info HostInfo) {
	if info.IsLocal() {
		return
	}
	r.entries[strings.ToLower(info.Name)] = hostinfoDefaults(info)
}

func (r *Registry) Unregister(name string) error {
	name = strings.ToLower(name)
	if name == LocalHost || name == "" {
		return fmt.Errorf("cannot unregister the local host")
	}
	if _, ok := r.entries[name]; !ok {
		return fmt.Errorf("host %q is not registered", name)
	}
	delete(r.entries, name)
	return nil
}

// List returns the local host first, then the remote hosts in sorted order.
func (r *Registry) List() []HostInfo {
	out := []HostInfo{{Name: LocalHost}}
	for _, name := range sortedKeys(r.entries) {
		out = append(out, hostinfoDefaults(r.entries[name]))
	}
	return out
}

func hostinfoDefaults(h HostInfo) HostInfo {
	if h.RemoteCmd == "" {
		h.RemoteCmd = "systemd-stdio-bridge"
	}
	return h
}

func sortedKeys(m map[string]HostInfo) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}

// hasPort reports whether addr already carries a port.
func hasPort(addr string) bool {
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}

// sshTarget normalises a host to host:port for the SSH dial.
func sshTarget(h HostInfo) string {
	target := h.Target
	if target == "" {
		return ""
	}
	if !hasPort(target) {
		target += ":22"
	}
	return target
}

// dialRemote opens a systemd D-Bus connection to h over SSH.
func dialRemote(ctx context.Context, h HostInfo) (DbusConnection, error) {
	cfg, err := sshClientConfig(h)
	if err != nil {
		return nil, err
	}
	if h.Target == "" {
		return nil, fmt.Errorf("host %q has no target address", h.Name)
	}
	conn, err := extdbus.NewSSHConnection(ctx, cfg, sshTarget(h), h.RemoteCmd)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// sshClientConfig builds an SSH client config for h: it consults the local
// ssh-agent first, then any explicit key file; host-key verification uses the
// provided (or ~/.ssh/known_hosts) file unless Insecure is set.
func sshClientConfig(h HostInfo) (*ssh.ClientConfig, error) {
	cfg := &ssh.ClientConfig{
		Timeout: 10 * time.Second,
	}
	if h.User != "" {
		cfg.User = h.User
	} else if u := os.Getenv("USER"); u != "" {
		cfg.User = u
	} else if pu, err := osuser.Current(); err == nil {
		cfg.User = pu.Username
	}

	var signers []ssh.Signer
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			defer conn.Close()
			if as, err := agent.NewClient(conn).Signers(); err == nil {
				signers = append(signers, as...)
			}
		}
	}
	keyFile := h.KeyFile
	if keyFile == "" {
		keyFile = defaultKeyFile()
	}
	if keyFile != "" {
		if raw, err := os.ReadFile(filepath.Clean(keyFile)); err == nil {
			if signer, err := ssh.ParsePrivateKey(raw); err == nil {
				signers = append(signers, signer)
			}
		}
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("no SSH key available for host %q: provide key_file or run ssh-add (passphrase-protected keys must be loaded into the agent)", h.Name)
	}
	cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signers...)}

	if h.Insecure {
		cfg.HostKeyCallback = ssh.InsecureIgnoreHostKey() // testing only
	} else {
		known := h.KnownHosts
		if known == "" {
			known = knownHostsFile()
		}
		if known == "" {
			return nil, fmt.Errorf("no known_hosts for host %q: set known_hosts or insecure", h.Name)
		}
		callback, err := knownhosts.New(known)
		if err != nil {
			return nil, fmt.Errorf("parse known_hosts %q: %w", known, err)
		}
		cfg.HostKeyCallback = callback
	}
	return cfg, nil
}

func defaultKeyFile() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	for _, f := range []string{"id_ed25519", "id_rsa"} {
		p := filepath.Join(home, ".ssh", f)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func knownHostsFile() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	p := filepath.Join(home, ".ssh", "known_hosts")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}
