package systemd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/openSUSE/systemd-mcp/internal/pkg/extdbus"
)

// Registry stores the bus endpoints the server can talk to. The local host
// (LocalHost) is always available without any registration. A small
// process-scoped trust store remembers host keys the user has explicitly
// accepted, so an already-prompted host does not prompt again within the
// same server run.
type Registry struct {
	mu      sync.Mutex
	entries map[string]HostInfo
	// trusted holds host keys the user has explicitly accepted, keyed by the
	// lower-cased host name. It is process-scoped: restarting the server
	// clears it, so a first connection to a new host will prompt again.
	trusted map[string][]TrustedHostKey
}

// NewRegistry creates a registry
func NewRegistry() *Registry {
	return &Registry{
		entries: map[string]HostInfo{},
		trusted: map[string][]TrustedHostKey{},
	}
}

// TrustedHostKey is an SSH host key the user has explicitly accepted for a
// registered host. Raw is base64(ssh.Marshal(k)) so it can be re-parsed and
// byte-compared against future presentations of the same key.
type TrustedHostKey struct {
	Name       string    `json:"name"`
	Target     string    `json:"target"`
	KeyType    string    `json:"key_type"`
	Raw        string    `json:"raw"`
	Finger     string    `json:"fingerprint"`
	AcceptedAt time.Time `json:"accepted_at"`
}

// TrustedKeys returns a copy of the keys the user has trusted for name.
func (r *Registry) TrustedKeys(name string) []TrustedHostKey {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]TrustedHostKey, len(r.trusted[strings.ToLower(name)]))
	copy(out, r.trusted[strings.ToLower(name)])
	return out
}

// Trust records that the user accepted key for the registered host name.
func (r *Registry) Trust(name, target string, key ssh.PublicKey) {
	if r == nil || key == nil {
		return
	}
	name = strings.ToLower(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.trusted[name] = append(r.trusted[name], TrustedHostKey{
		Name:       name,
		Target:     target,
		KeyType:    key.Type(),
		Raw:        base64.StdEncoding.EncodeToString(key.Marshal()),
		Finger:     ssh.FingerprintSHA256(key),
		AcceptedAt: time.Now().UTC(),
	})
}

// IsTrusted reports whether key has been accepted by the user for name.
func (r *Registry) IsTrusted(name string, key ssh.PublicKey) bool {
	if r == nil || key == nil {
		return false
	}
	name = strings.ToLower(name)
	raw := base64.StdEncoding.EncodeToString(key.Marshal())
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, k := range r.trusted[name] {
		if k.Raw == raw {
			return true
		}
	}
	return false
}

// Get resolves a requested host name to a concrete HostInfo. The local host
// (LocalHost) is always available; any other name must already be registered.
func (r *Registry) Get(name string) (HostInfo, error) {
	name = strings.ToLower(name)
	if name == "" || name == LocalHost {
		return HostInfo{Name: LocalHost}, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	info, ok := r.entries[name]
	if !ok {
		return HostInfo{}, fmt.Errorf("host %q is not registered as a remote host; add it with the set_host tool (action='register')", name)
	}
	return info, nil
}

// PreconfigureHosts adds remote hosts supplied at server startup.
// Each entry is:
//
//	name:target[,user=U][,key_file=K][,password=P][,known_hosts=F][,insecure][,remote_cmd=C]
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
			case strings.HasPrefix(tok, "password="):
				info.Password = strings.TrimSpace(strings.TrimPrefix(tok, "password="))
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
	r.mu.Lock()
	r.entries[strings.ToLower(info.Name)] = hostinfoDefaults(info)
	r.mu.Unlock()
}

// Unregister removes a remote host and clears any trusted host keys for it,
// so re-registering the host prompts the user about its key again.
func (r *Registry) Unregister(name string) error {
	name = strings.ToLower(name)
	if name == LocalHost || name == "" {
		return fmt.Errorf("cannot unregister the local host")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[name]; !ok {
		return fmt.Errorf("host %q is not registered", name)
	}
	delete(r.entries, name)
	delete(r.trusted, name)
	return nil
}

// List returns the local host first, then the remote hosts in sorted order.
func (r *Registry) List() []HostInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
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

// dialRemote opens a systemd D-Bus connection to h over SSH. If the first
// connection to h presents a host key the user has not yet seen, onUnknown is
// invoked; returning false cancels the dial.
func dialRemote(ctx context.Context, h HostInfo, trusted func(ssh.PublicKey) bool, onUnknown func(ssh.PublicKey) bool) (DbusConnection, error) {
	cfg, err := sshClientConfig(h, trusted, onUnknown)
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
// ssh-agent first, then any explicit key file, and offers a password when one
// is registered for the host.
//
// Host-key verification:
//   - If h.Insecure is set the callback always accepts (testing only).
//   - Otherwise the key is checked against the trusted store (callback
//     `trusted`), then (when h.KnownHosts is set) against that file. A key
//     that matches neither is forwarded to `onUnknown`, which decides whether
//     to accept / reject it (e.g. by eliciting the user). A key that
//     contradicts a trusted entry is always rejected (possible MITM).
func sshClientConfig(h HostInfo, trusted func(ssh.PublicKey) bool, onUnknown func(ssh.PublicKey) bool) (*ssh.ClientConfig, error) {
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
	if len(signers) > 0 {
		cfg.Auth = append(cfg.Auth, ssh.PublicKeys(signers...))
	}
	if h.Password != "" {
		cfg.Auth = append(cfg.Auth, ssh.Password(h.Password))
	}
	if len(cfg.Auth) == 0 {
		return nil, fmt.Errorf("no SSH auth available for host %q: provide key_file or run ssh-add, or register the host with a password", h.Name)
	}

	if h.Insecure {
		cfg.HostKeyCallback = ssh.InsecureIgnoreHostKey() // testing only
		return cfg, nil
	}

	var knownCallback ssh.HostKeyCallback
	knownFile := h.KnownHosts
	if knownFile == "" {
		knownFile = knownHostsFile() // ~/.ssh/known_hosts when it exists
	}
	if knownFile != "" {
		callback, err := knownhosts.New(knownFile)
		if err != nil {
			return nil, fmt.Errorf("parse known_hosts %q: %w", knownFile, err)
		}
		knownCallback = callback
	}

	cfg.HostKeyCallback = hostKeyCallback(trusted, knownCallback, onUnknown)
	return cfg, nil
}

// hostKeyCallback builds an ssh.HostKeyCallback that consults, in order:
//  1. the process-scoped trusted store (a user previously accepted the key for this host name)
//  2. the given known_hosts callback (if any; a mismatch is fatal)
//  3. the onUnknown callback (typically an elicitation to the user, who can
//     then accept or ignore the unseen key)
func hostKeyCallback(trusted func(ssh.PublicKey) bool, known ssh.HostKeyCallback, onUnknown func(ssh.PublicKey) bool) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if trusted != nil && trusted(key) {
			return nil
		}
		if known != nil {
			err := known(hostname, remote, key)
			if err == nil {
				return nil
			}
			var keyErr *knownhosts.KeyError
			if errors.As(err, &keyErr) && len(keyErr.Want) > 0 {
				return err // a mismatch with a known key is a MITM indicator
			}
			// no known_hosts entry for this host (or a parse error) — fall through
		}
		if onUnknown != nil && onUnknown(key) {
			return nil
		}
		return fmt.Errorf("host key for the remote host %q was not trusted and was not accepted by the user", hostname)
	}
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

// acceptHostKey is the onUnknown host-key hook. It presents the unknown (or
// changed) SSH host key to the user via an elicitation and returns true only
// if the user accepts it. On accept the key is stored in the registry's
// trust store for the lifetime of the server run; on decline or cancel the
// connection is refused.
func (conn *Connection) acceptHostKey(ctx context.Context, session *mcp.ServerSession, h HostInfo, key ssh.PublicKey) bool {
	finger := ssh.FingerprintSHA256(key)
	base64Key := base64.StdEncoding.EncodeToString(key.Marshal())

	if session == nil {
		// No interactive client (e.g. tests, headless): refuse an untrusted
		// key rather than silently accepting it.
		return false
	}

	msg := fmt.Sprintf(
		"The SSH host key presented by %q (target %s) is not in any known_hosts file and has not been trusted "+
			"before.\n\n"+
			"Key type: %s\nFingerprint (SHA256): %s\nPublic key: %s %s\n\n"+
			"Verify this key is correct for the host (for example by comparing the fingerprint with out-of-band "+
			"information). Accept to trust it for this server run and connect, or ignore to refuse the connection.",
		h.Name, h.Target, key.Type(), finger, key.Type(), base64Key)

	schema := &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"accept": {Type: "boolean", Description: "Accept and trust the host key"},
		},
		Required: []string{"accept"},
	}

	req := &mcp.ElicitParams{
		Message:         msg,
		RequestedSchema: schema,
	}
	res, err := session.Elicit(ctx, req)
	if err != nil {
		return false
	}
	if res == nil || res.Action != "accept" {
		return false
	}
	if v, ok := res.Content["accept"]; ok {
		if b, ok := v.(bool); ok {
			if !b {
				return false
			}
		}
	}
	conn.reg.Trust(h.Name, h.Target, key)
	return true
}
