package systemd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	auth "github.com/openSUSE/systemd-mcp/authkeeper"
	"github.com/openSUSE/systemd-mcp/internal/pkg/extdbus"
	"github.com/openSUSE/systemd-mcp/internal/pkg/util"
	"golang.org/x/crypto/ssh"
)

// DbusConnection is the subset of a systemd D-Bus connection the tools use.
// The concrete implementation is go-systemd's *dbus Conn (local bus) or
// extdbus.Conn (which embeds it and rides the bus over SSH); the interface is
// the seam that lets a single set of handlers serve both.
type DbusConnection interface {
	ListUnitsByPatternsContext(ctx context.Context, states []string, patterns []string) ([]dbus.UnitStatus, error)
	GetAllPropertiesContext(ctx context.Context, unitName string) (map[string]interface{}, error)
	ReloadOrRestartUnitContext(ctx context.Context, name string, mode string, ch chan<- string) (int, error)
	RestartUnitContext(ctx context.Context, name string, mode string, ch chan<- string) (int, error)
	StartUnitContext(ctx context.Context, name string, mode string, ch chan<- string) (int, error)
	StopUnitContext(ctx context.Context, name string, mode string, ch chan<- string) (int, error)
	KillUnitContext(ctx context.Context, name string, signal int32)
	EnableUnitFilesContext(ctx context.Context, files []string, runtime bool, force bool) (bool, []dbus.EnableUnitFileChange, error)
	DisableUnitFilesContext(ctx context.Context, files []string, runtime bool) ([]dbus.DisableUnitFileChange, error)
	ListUnitFilesContext(ctx context.Context) ([]dbus.UnitFile, error)

	Close()
}

// ErrNoLocalBus is returned for a local call when the server has no local
// system bus connection (it could not connect one at startup).
var ErrNoLocalBus = errors.New("the local system bus is not available")

type Connection struct {
	reg     *Registry
	auth    auth.AuthKeeper
	Encoder util.OutputEncoding
	// dbus is this machine's own system bus (or a test mock). Remote hosts are
	// connected lazily, per call, from the registry.
	dbus     DbusConnection
	rchannel chan string
	// verifyConnect is invoked when a remote host is registered to establish a
	// real connection (SSH auth, host-key check and the D-Bus handshake) so the
	// registration can confirm the host is actually reachable and, if needed,
	// elicit the user about an untrusted host key. It defaults to the standard
	// dialRemote; tests override it to exercise the success/failure paths
	// deterministically.
	verifyConnect func(ctx context.Context, h HostInfo, session *mcp.ServerSession) error
	// fetchOSRelease reads the host's /etc/os-release over the same trusted
	// SSH connection the D-Bus bridge rides on, so a registration can capture
	// the underlying OS without a second connection or auth prompt. It returns
	// the raw file content; the caller parses and stores it on HostInfo. It
	// defaults to a RunRemote of `cat /etc/os-release`; tests override it to
	// deterministically return canned content or an error.
	fetchOSRelease func(ctx context.Context, req *mcp.CallToolRequest, h HostInfo) (string, error)
	// fetchHostname reads the host's /etc/hostname over the same trusted SSH
	// connection, so a registration can derive a stable, human-meaningful host
	// name from the remote machine itself. It returns the trimmed hostname (an
	// empty string when the file is absent); the caller decides how to use it.
	// It defaults to running `cat /etc/hostname 2>/dev/null`; tests override it
	// to deterministically return canned content or an error.
	fetchHostname func(ctx context.Context, req *mcp.CallToolRequest, h HostInfo) (string, error)
}

// NewSystem builds a host-aware connection. It is local-bus independent: the
// local bus is opened lazily via ConnectLocal so the set_host tool stays usable
// even where no local system bus is available.
func NewSystem(auth auth.AuthKeeper, reg *Registry) *Connection {
	c := &Connection{
		reg:      reg,
		auth:     auth,
		rchannel: make(chan string, 1),
	}
	c.verifyConnect = c.verifyHostConnect
	c.fetchOSRelease = c.fetchRemoteOSRelease
	c.fetchHostname = c.fetchRemoteHostname
	return c
}

// fetchRemoteHostname reads the host's /etc/hostname over the same trusted SSH
// connection fetchRemoteOSRelease rides on, so no second connection, auth or
// host-key prompt is needed. It returns the trimmed hostname, or an empty
// string (with a non-fatal error) when the file is absent.
func (conn *Connection) fetchRemoteHostname(ctx context.Context, req *mcp.CallToolRequest, h HostInfo) (string, error) {
	stdout, _, code, err := conn.runOnHost(ctx, h, req, "cat /etc/hostname 2>/dev/null")
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("cat /etc/hostname exited with status %d: %s", code, strings.TrimSpace(stdout))
	}
	return strings.TrimSpace(stdout), nil
}

// fetchRemoteOSRelease reads the host's /etc/os-release over the same trusted
// SSH connection the D-Bus bridge rides on (directly from the HostInfo, so it
// works even before the host is stored in the registry), meaning no second
// connection, no new auth, and no new host-key prompt. It returns the raw file
// content; the caller parses and stores it on HostInfo. Any error is non-fatal
// to registration — the OS is simply left empty.
func (conn *Connection) fetchRemoteOSRelease(ctx context.Context, req *mcp.CallToolRequest, h HostInfo) (string, error) {
	stdout, _, code, err := conn.runOnHost(ctx, h, req, "cat /etc/os-release 2>/dev/null")
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("cat /etc/os-release exited with status %d: %s", code, strings.TrimSpace(stdout))
	}
	return stdout, nil
}

// verifyHostConnect establishes a real connection (SSH auth, host-key check
// and the D-Bus handshake) to h so a registration can confirm the host is
// reachable and, if needed, elicit the user about an untrusted host key. The
// connection is torn down again before returning. Tests may override
// conn.verifyConnect to exercise the success/failure paths deterministically.
func (conn *Connection) verifyHostConnect(ctx context.Context, h HostInfo, session *mcp.ServerSession) error {
	c, err := dialRemote(ctx, h,
		func(key ssh.PublicKey) bool { return conn.reg.IsTrusted(h.Name, key) },
		func(key ssh.PublicKey) bool { return conn.acceptHostKey(ctx, session, h, key) })
	if err != nil {
		return err
	}
	c.Close()
	return nil
}

// ConnectLocal opens this machine's own system bus for the local tools.
// Failure is not fatal: remote hosts (registered via set_host or preconfigured
// at startup) remain operable without a local bus.
func (conn *Connection) ConnectLocal(ctx context.Context) error {
	local, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return err
	}
	conn.dbus = local
	return nil
}

// connectionFor resolves the bus endpoint for a host name: this machine's own
// system bus for the local host, and a lazily opened SSH D-Bus connection for a
// registered remote host. It returns the DbusConnection for that endpoint, a
// channel the endpoint uses to report async job results, and whether the caller
// owns the connection (i.e. must Close it when done — true only for the
// per-call remote connections).
func (conn *Connection) connectionFor(ctx context.Context, hostName string, session *mcp.ServerSession) (DbusConnection, chan string, bool, error) {
	if conn.reg != nil {
		info, err := conn.reg.Get(hostName)
		if err != nil {
			return nil, nil, false, err
		}
		if !info.IsLocal() {
			remote, err := dialRemote(ctx, info,
				func(key ssh.PublicKey) bool { return conn.reg.IsTrusted(info.Name, key) },
				func(key ssh.PublicKey) bool { return conn.acceptHostKey(ctx, session, info, key) })
			if err != nil {
				return nil, nil, false, err
			}
			return remote, make(chan string, 1), true, nil
		}
	}
	local := conn.dbus
	if local == nil {
		return nil, nil, false, ErrNoLocalBus
	}
	return local, conn.rchannel, false, nil
}

// withConn resolves the endpoint for an (already defaulted) host name, opens it
// if remote, and closes it again when fn returns — so each call opens and tears
// down exactly one remote bus connection. fn receives the ready DbusConnection
// and a channel that carries the async job result for that call.
//
// The MCP request (req) is passed in so an unknown SSH host key can be
// elicited from the current client (req may be nil in tests or headless use).
func (conn *Connection) withConn(ctx context.Context, hostName string, req *mcp.CallToolRequest, fn func(dc DbusConnection, ch chan string) (*mcp.CallToolResult, any, error)) (*mcp.CallToolResult, any, error) {
	var session *mcp.ServerSession
	if req != nil {
		session = req.Session
	}
	dc, ch, owned, err := conn.connectionFor(ctx, hostName, session)
	if err != nil {
		return nil, nil, err
	}
	if owned {
		defer dc.Close()
	}
	return fn(dc, ch)
}

// RunRemote executes command on a remote host over SSH, returning stdout,
// stderr and the process exit status. It reuses the exact same host registry
// and sshClientConfig as the D-Bus tools, so the registered host's user,
// key_file/password, known_hosts, insecure flag and the user's process-scoped
// accepted-host-keys store all apply — and an unknown host key is elicited
// from the current client the same way a first D-Bus connection is. It is only
// usable for registered remote hosts; for the local host (LocalHost / "") it
// returns ErrNoLocalBus so the caller can fall back to a local implementation.
func (conn *Connection) RunRemote(ctx context.Context, req *mcp.CallToolRequest, hostName, command string) (string, string, int, error) {
	info, err := conn.reg.Get(hostName)
	if err != nil {
		return "", "", 0, err
	}
	if info.IsLocal() {
		return "", "", 0, ErrNoLocalBus
	}
	return conn.runOnHost(ctx, info, req, command)
}

// runOnHost dials the given (registered or not) remote host and runs command
// on it over the SSH session channel. It takes the HostInfo directly so it can
// be used for a host being registered (not yet in the registry), reusing the
// same trusted-store / host-key elicitation as every other remote call.
func (conn *Connection) runOnHost(ctx context.Context, info HostInfo, req *mcp.CallToolRequest, command string) (string, string, int, error) {
	var session *mcp.ServerSession
	if req != nil {
		session = req.Session
	}
	remote, err := dialRemote(ctx, info,
		func(key ssh.PublicKey) bool { return conn.reg.IsTrusted(info.Name, key) },
		func(key ssh.PublicKey) bool { return conn.acceptHostKey(ctx, session, info, key) })
	if err != nil {
		return "", "", 0, err
	}
	defer remote.Close()

	c, ok := remote.(*extdbus.Conn)
	if !ok {
		return "", "", 0, fmt.Errorf("remote connection is not an SSH channel and cannot run %q", command)
	}
	return c.Run(ctx, command)
}

// Close closes the local bus connection and the shared job channel. Remote
// connections are short-lived and closed per call, so nothing else to release.
func (conn *Connection) Close() {
	if conn.dbus != nil {
		conn.dbus.Close()
	}
	if conn.rchannel != nil {
		close(conn.rchannel)
	}
}
