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

	// register a remote host with a specific (non-generic) name: it is honored
	_, _, err := conn.SetHost(ctx, nil, &SetHostParams{Action: "register", Host: "web1", Target: "10.0.0.5", User: "admin"})
	assert.NoError(t, err)

	// a generic host name (the local-host synonym) is not used as the
	// identifier; the host is instead given a deterministic derived unique name
	res, _, err := conn.SetHost(ctx, nil, &SetHostParams{Action: "register", Host: LocalHost, Target: "10.0.0.9"})
	assert.NoError(t, err)
	expected := uniqueNameForTarget("10.0.0.9")
	assert.Contains(t, hostText(res), expected)
	_, err = conn.reg.Get(expected)
	assert.NoError(t, err, "the host must be registered under its derived name")

	// list should include the local host, web1, and the derived name
	res, _, err = conn.SetHost(ctx, nil, &SetHostParams{Action: "list"})
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

// TestResolveHostName covers the naming rule: the remote /etc/hostname wins
// when present and non-generic, otherwise the caller's (non-generic) name, and
// otherwise a derived unique name; a generic caller name is never used.
func TestResolveHostName(t *testing.T) {
	// a real /etc/hostname is used directly
	assert.Equal(t, "web1", resolveHostName("", "web1", "10.0.0.5"))
	assert.Equal(t, "db.example.com", resolveHostName("ignored", "db.example.com", "10.0.0.7"))

	// empty /etc/hostname falls back to a non-generic caller name
	assert.Equal(t, "web1", resolveHostName("web1", "", "10.0.0.5"))

	// a generic /etc/hostname falls back to a non-generic caller name
	assert.Equal(t, "web1", resolveHostName("web1", "linux", "10.0.0.5"))
	assert.Equal(t, "myhost", resolveHostName("myhost", LocalHost, "10.0.0.5"))

	// generic /etc/hostname plus a generic (or empty) caller name yields a
	// deterministic unique name derived from the target
	assert.Equal(t, uniqueNameForTarget("10.0.0.5"), resolveHostName(LocalHost, "linux", "10.0.0.5"))
	assert.Equal(t, uniqueNameForTarget("10.0.0.5"), resolveHostName("", "", "10.0.0.5"))
	assert.Equal(t, uniqueNameForTarget("10.0.0.5"), resolveHostName("", "localhost", "10.0.0.5"))

	// a caller name equal to the local-host synonym is never used verbatim
	assert.Equal(t, uniqueNameForTarget("10.0.0.5"), resolveHostName(LocalHost, "", "10.0.0.5"))
}

// TestUniqueNameForTarget checks the derived name is stable per target and that
// different targets produce different names.
func TestUniqueNameForTarget(t *testing.T) {
	a := uniqueNameForTarget("10.0.0.5")
	b := uniqueNameForTarget("10.0.0.6")
	assert.Equal(t, a, uniqueNameForTarget("10.0.0.5"), "same target -> same name")
	assert.NotEqual(t, a, b, "different targets -> different names")
	for _, n := range []string{a, b} {
		assert.NotEmpty(t, n)
		assert.NotEqual(t, LocalHost, strings.ToLower(n))
		assert.False(t, isGenericName(n))
	}
}

// TestSetHostRegisterDerivesNameFromHostname verifies registration uses the
// remote /etc/hostname when it is present and non-generic, and reports that
// name in the reply and in `list`.
func TestSetHostRegisterDerivesNameFromHostname(t *testing.T) {
	auth, _ := auth_pkg.NewNoAuth(true, true)
	conn := &Connection{
		reg:      NewRegistry(),
		auth:     auth,
		rchannel: make(chan string, 1),
	}
	ctx := context.Background()
	conn.verifyConnect = func(ctx context.Context, h HostInfo, session *mcp.ServerSession) error { return nil }
	conn.fetchHostname = func(ctx context.Context, req *mcp.CallToolRequest, h HostInfo) (string, error) {
		return "dbserver9", nil
	}

	// The caller passes a generic name; the remote /etc/hostname should win.
	res, _, err := conn.SetHost(ctx, nil, &SetHostParams{Action: "register", Host: LocalHost, Target: "10.0.0.5"})
	assert.NoError(t, err)
	assert.Contains(t, hostText(res), "dbserver9")
	_, err = conn.reg.Get("dbserver9")
	assert.NoError(t, err)

	// and it should appear in `list`
	lres, _, err := conn.SetHost(ctx, nil, &SetHostParams{Action: "list"})
	assert.NoError(t, err)
	assert.Contains(t, hostText(lres), "dbserver9")
}

// TestSetHostRegisterGenericHostnameFallsBackToCaller verifies that when the
// remote /etc/hostname is generic (e.g. "linux"), the caller's non-generic
// name is used instead.
func TestSetHostRegisterGenericHostnameFallsBackToCaller(t *testing.T) {
	auth, _ := auth_pkg.NewNoAuth(true, true)
	conn := &Connection{
		reg:      NewRegistry(),
		auth:     auth,
		rchannel: make(chan string, 1),
	}
	ctx := context.Background()
	conn.verifyConnect = func(ctx context.Context, h HostInfo, session *mcp.ServerSession) error { return nil }
	conn.fetchHostname = func(ctx context.Context, req *mcp.CallToolRequest, h HostInfo) (string, error) {
		return "linux", nil
	}

	res, _, err := conn.SetHost(ctx, nil, &SetHostParams{Action: "register", Host: "web1", Target: "10.0.0.5"})
	assert.NoError(t, err)
	assert.Contains(t, hostText(res), "web1")
	_, err = conn.reg.Get("web1")
	assert.NoError(t, err)
}

// TestSetHostRegisterGenericHostnameAndCallerYieldsUnique verifies that when
// both the remote /etc/hostname and the caller's name are generic (or empty), a
// deterministic unique name derived from the target is used and reported.
func TestSetHostRegisterGenericHostnameAndCallerYieldsUnique(t *testing.T) {
	auth, _ := auth_pkg.NewNoAuth(true, true)
	conn := &Connection{
		reg:      NewRegistry(),
		auth:     auth,
		rchannel: make(chan string, 1),
	}
	ctx := context.Background()
	conn.verifyConnect = func(ctx context.Context, h HostInfo, session *mcp.ServerSession) error { return nil }
	conn.fetchHostname = func(ctx context.Context, req *mcp.CallToolRequest, h HostInfo) (string, error) {
		return "linux", nil
	}

	expected := uniqueNameForTarget("10.0.0.5")
	// caller name is a generic placeholder ("linux"), so it must not be used
	_, _, err := conn.SetHost(ctx, nil, &SetHostParams{Action: "register", Host: "linux", Target: "10.0.0.5"})
	assert.NoError(t, err)
	_, err = conn.reg.Get(expected)
	assert.NoError(t, err, "must be registered under the derived unique name")
	_, err = conn.reg.Get("linux")
	assert.Error(t, err, "the generic name must not be used as the identifier")
}

// TestSetHostRegisterHostnameUnreadable still registers (best-effort), deriving
// its name from the caller/target inputs.
func TestSetHostRegisterHostnameUnreadable(t *testing.T) {
	auth, _ := auth_pkg.NewNoAuth(true, true)
	conn := &Connection{
		reg:      NewRegistry(),
		auth:     auth,
		rchannel: make(chan string, 1),
	}
	ctx := context.Background()
	conn.verifyConnect = func(ctx context.Context, h HostInfo, session *mcp.ServerSession) error { return nil }
	conn.fetchHostname = func(ctx context.Context, req *mcp.CallToolRequest, h HostInfo) (string, error) {
		return "", fmt.Errorf("cat: /etc/hostname: No such file or directory")
	}

	// caller supplied a specific name -> it is used
	_, _, err := conn.SetHost(ctx, nil, &SetHostParams{Action: "register", Host: "web1", Target: "10.0.0.5"})
	assert.NoError(t, err)
	_, err = conn.reg.Get("web1")
	assert.NoError(t, err)

	// no usable name anywhere -> unique derived name
	expected := uniqueNameForTarget("10.0.0.6")
	_, _, err = conn.SetHost(ctx, nil, &SetHostParams{Action: "register", Host: "", Target: "10.0.0.6"})
	assert.NoError(t, err)
	_, err = conn.reg.Get(expected)
	assert.NoError(t, err)
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
