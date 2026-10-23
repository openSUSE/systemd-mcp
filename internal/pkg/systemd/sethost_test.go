package systemd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
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

	// A successful registration is confirmed by a real (mock) connection: the
	// host is only stored when verifyConnect succeeds.
	conn.verifyConnect = func(ctx context.Context, h HostInfo, session *mcp.ServerSession) error {
		return nil
	}

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

// TestSetHostRegisterCapturesOSRelease verifies that registration best-effort
// reads the host's /etc/os-release over the trusted SSH connection and stores
// it on the HostInfo — and that the result and the subsequent `list` output
// carry the captured OS. A failure to read /etc/os-release must not fail the
// registration: the host still stores with an empty OS.
func TestSetHostRegisterCapturesOSRelease(t *testing.T) {
	auth, _ := auth_pkg.NewNoAuth(true, true)
	conn := &Connection{
		reg:      NewRegistry(),
		auth:     auth,
		rchannel: make(chan string, 1),
	}
	ctx := context.Background()
	conn.verifyConnect = func(ctx context.Context, h HostInfo, session *mcp.ServerSession) error {
		return nil
	}

	const sample = `NAME="openSUSE Leap"
VERSION="15.6"
ID="opensuse-leap"
ID_LIKE="suse opensuse"
VERSION_ID="15.6"
PRETTY_NAME="openSUSE Leap 15.6"
ANSI_COLOR="38;2;141;77;131"
ANSI_ICON_NAME="openSUSE-15.6"
`
	conn.fetchOSRelease = func(ctx context.Context, req *mcp.CallToolRequest, h HostInfo) (string, error) {
		return sample, nil
	}

	// register: the OS should be captured, parsed and stored.
	res, _, err := conn.SetHost(ctx, nil, &SetHostParams{Action: "register", Host: "web1", Target: "10.0.0.5", User: "admin"})
	assert.NoError(t, err)
	assert.Contains(t, hostText(res), "web1")
	assert.Contains(t, hostText(res), "openSUSE Leap 15.6")

	info, err := conn.reg.Get("web1")
	assert.NoError(t, err)
	assert.Equal(t, "openSUSE Leap", info.OS.Name)
	assert.Equal(t, "15.6", info.OS.Version)
	assert.Equal(t, "opensuse-leap", info.OS.ID)
	assert.Equal(t, "suse opensuse", info.OS.IDLike)
	assert.Equal(t, "openSUSE Leap 15.6", info.OS.PrettyName)
	assert.Equal(t, "openSUSE Leap 15.6", info.OS.String())

	// `list` should surface the captured OS as well.
	lres, _, err := conn.SetHost(ctx, nil, &SetHostParams{Action: "list"})
	assert.NoError(t, err)
	assert.Contains(t, hostText(lres), "web1")
	assert.Contains(t, hostText(lres), "openSUSE Leap 15.6")
}

// TestSetHostRegisterSucceedsWhenOSReleaseUnavailable verifies the OS read is
// strictly best-effort: a host is still registered when /etc/os-release cannot
// be read (e.g. no such file on the remote), just without an OS attached.
func TestSetHostRegisterSucceedsWhenOSReleaseUnavailable(t *testing.T) {
	auth, _ := auth_pkg.NewNoAuth(true, true)
	conn := &Connection{
		reg:      NewRegistry(),
		auth:     auth,
		rchannel: make(chan string, 1),
	}
	ctx := context.Background()
	conn.verifyConnect = func(ctx context.Context, h HostInfo, session *mcp.ServerSession) error {
		return nil
	}
	conn.fetchOSRelease = func(ctx context.Context, req *mcp.CallToolRequest, h HostInfo) (string, error) {
		return "", fmt.Errorf("cat: /etc/os-release: No such file or directory")
	}

	_, _, err := conn.SetHost(ctx, nil, &SetHostParams{Action: "register", Host: "web2", Target: "10.0.0.6"})
	assert.NoError(t, err, "registration must succeed even if /etc/os-release is unreadable")

	info, err := conn.reg.Get("web2")
	assert.NoError(t, err)
	assert.Empty(t, info.OS.String(), "OS must be empty when it could not be read")
}

func TestParseOSRelease(t *testing.T) {
	const content = `# /etc/os-release: OS-release variables
NAME="openSUSE Tumbleweed"
VERSION="20261001"
ID="opensuse-tumbleweed"
ID_LIKE=suse
VERSION_ID="20261001"
PRETTY_NAME="openSUSE Tumbleweed"
ANSI_COLOR="38;2;143;101;146"
ANSI_ICON_NAME="openSUSE"
`
	rel := parseOSRelease(content)
	assert.Equal(t, "openSUSE Tumbleweed", rel.Name)
	assert.Equal(t, "20261001", rel.Version)
	assert.Equal(t, "opensuse-tumbleweed", rel.ID)
	assert.Equal(t, "suse", rel.IDLike)
	assert.Equal(t, "openSUSE Tumbleweed", rel.PrettyName)
	assert.Equal(t, "openSUSE Tumbleweed 20261001", rel.String())
}

func TestParseOSReleaseEmptyAndIgnoredComments(t *testing.T) {
	rel := parseOSRelease("# only comments\n\nNAME=\n")
	assert.Zero(t, rel.String())

	rel = parseOSRelease("NAME=Alpine Linux\nID=alpine\n")
	assert.Equal(t, "Alpine Linux", rel.Name)
	assert.Equal(t, "alpine", rel.ID)
}

func TestUnquoteOSRelease(t *testing.T) {
	assert.Equal(t, "value", unquoteOSRelease("value"))
	assert.Equal(t, "openSUSE Leap", unquoteOSRelease(`"openSUSE Leap"`))
	assert.Equal(t, "it's", unquoteOSRelease(`'it's'`))
	assert.Equal(t, "a\"b", unquoteOSRelease(`"a\"b"`))
	assert.Equal(t, "new\nline", unquoteOSRelease(`"new\nline"`))
}

// TestSetHostRegisterRefusesUnreachableHost verifies that a registration does
// not succeed (and does not store the host) when the trial connection fails —
// for example when the remote host's host key is untrusted and not accepted.
func TestSetHostRegisterRefusesUnreachableHost(t *testing.T) {
	auth, _ := auth_pkg.NewNoAuth(true, true)
	conn := &Connection{
		reg:      NewRegistry(),
		auth:     auth,
		rchannel: make(chan string, 1),
	}
	ctx := context.Background()

	conn.verifyConnect = func(context.Context, HostInfo, *mcp.ServerSession) error {
		return fmt.Errorf("host key for the remote host was not trusted and was not accepted by the user")
	}

	_, _, err := conn.SetHost(ctx, nil, &SetHostParams{Action: "register", Host: "web1", Target: "10.0.0.5"})
	assert.Error(t, err)

	// the host must not be registered because verification failed
	_, ok := conn.reg.entries["web1"]
	assert.False(t, ok, "a failed registration must not store the host")
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
