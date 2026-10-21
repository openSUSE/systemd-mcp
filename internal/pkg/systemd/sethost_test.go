package systemd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	auth_pkg "github.com/openSUSE/systemd-mcp/authkeeper"
	"github.com/openSUSE/systemd-mcp/internal/pkg/util"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

func TestEffectiveHost(t *testing.T) {
	local := util.LocalHostName()
	assert.Equal(t, local, effectiveHost(""))
	assert.Equal(t, local, effectiveHost(LocalHost))
	assert.Equal(t, "web1", effectiveHost("web1"))
}

func hostText(res *mcp.CallToolResult) string {
	return res.Content[0].(*mcp.TextContent).Text
}

func TestSetHostActions(t *testing.T) {
	auth, _ := auth_pkg.NewNoAuth(true, true)
	conn := &Connection{
		reg:      NewRegistry(),
		auth:     auth,
		rchannel: make(chan string, 1),
	}
	ctx := context.Background()

	// register a remote host
	_, _, err := conn.SetHost(ctx, nil, &SetHostParams{Action: "register", Host: "web1", Target: "10.0.0.5", User: "admin"})
	assert.NoError(t, err)

	// registering the local host is refused
	_, _, err = conn.SetHost(ctx, nil, &SetHostParams{Action: "register", Host: LocalHost, Target: "10.0.0.5"})
	assert.Error(t, err)

	// list should include the local and web1 hosts
	res, _, err := conn.SetHost(ctx, nil, &SetHostParams{Action: "list"})
	assert.NoError(t, err)
	assert.Contains(t, hostText(res), "web1")
	assert.Contains(t, hostText(res), LocalHost)

	// unregister web1
	_, _, err = conn.SetHost(ctx, nil, &SetHostParams{Action: "unregister", Host: "web1"})
	assert.NoError(t, err)
}

func TestPreconfigureHosts(t *testing.T) {
	reg := NewRegistry()
	err := PreconfigureHosts(reg, []string{
		"web1:10.0.0.5,user=admin,key_file=/tmp/k,insecure,remote_cmd=foo",
		"db1:10.0.0.7:2222",
	})
	assert.NoError(t, err)

	names := make([]string, 0, len(reg.List()))
	for _, h := range reg.List() {
		names = append(names, h.Name)
		if h.Name == "web1" {
			assert.Equal(t, "10.0.0.5", h.Target)
			assert.Equal(t, "admin", h.User)
			assert.Equal(t, "/tmp/k", h.KeyFile)
			assert.True(t, h.Insecure)
			assert.Equal(t, "foo", h.RemoteCmd)
		}
		if h.Name == "db1" {
			assert.Equal(t, "10.0.0.7:2222", h.Target)
		}
	}
	assert.True(t, strings.Contains(strings.Join(names, ","), "web1"))
	assert.True(t, strings.Contains(strings.Join(names, ","), "db1"))

	// an entry without a name:target pair is rejected
	assert.Error(t, PreconfigureHosts(reg, []string{"orphan-no-target"}))
}

// fakeHostKey returns a fresh SSH public key (an Ed25519 key, generated at random).
func fakeHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap pubkey: %v", err)
	}
	return k
}

func TestRegistryTrustStore(t *testing.T) {
	reg := NewRegistry()
	key := fakeHostKey(t)
	other := fakeHostKey(t)

	// nothing is trusted yet
	assert.False(t, reg.IsTrusted("web1", key))
	assert.False(t, reg.IsTrusted("web1", other))

	// record an acceptance
	reg.Trust("Web1", "10.0.0.5", key)

	// lookups are case-insensitive on the host name
	assert.True(t, reg.IsTrusted("WEB1", key))
	assert.False(t, reg.IsTrusted("WEB1", other))

	// TrustedKeys reports the recorded key with its fingerprint
	keys := reg.TrustedKeys("web1")
	assert.Len(t, keys, 1)
	assert.Equal(t, ssh.FingerprintSHA256(key), keys[0].Finger)
	assert.Equal(t, "10.0.0.5", keys[0].Target)

	// unregistering the host clears its accepted keys
	reg.Register(HostInfo{Name: "web1", Target: "10.0.0.5"})
	assert.NoError(t, reg.Unregister("web1"))
	assert.False(t, reg.IsTrusted("web1", key))
	assert.Empty(t, reg.TrustedKeys("web1"))
}

func TestHostKeyCallback_TriggersOnUnknownAndAccepts(t *testing.T) {
	key := fakeHostKey(t)
	prompted := false
	cb := hostKeyCallback(
		func(k ssh.PublicKey) bool { return false }, // not trusted
		nil, // no known_hosts
		func(k ssh.PublicKey) bool { prompted = true; return true },
	)

	assert.NoError(t, cb("example.com", nil, key))
	assert.True(t, prompted, "the onUnknown hook must be called for an unknown key")
}

func TestHostKeyCallback_RejectsOnDecline(t *testing.T) {
	key := fakeHostKey(t)
	cb := hostKeyCallback(
		func(k ssh.PublicKey) bool { return false },
		nil,
		func(k ssh.PublicKey) bool { return false }, // user ignored the key
	)
	assert.Error(t, cb("example.com", nil, key))
}

func TestHostKeyCallback_AcceptsTrustedWithoutPrompting(t *testing.T) {
	key := fakeHostKey(t)
	prompted := false
	cb := hostKeyCallback(
		func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), key.Marshal()) }, // trusted
		nil,
		func(k ssh.PublicKey) bool { prompted = true; return false },
	)

	assert.NoError(t, cb("example.com", nil, key))
	assert.False(t, prompted, "a trusted key must not re-prompt")
}
