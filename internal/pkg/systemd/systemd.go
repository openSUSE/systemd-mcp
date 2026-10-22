package systemd

import (
	"context"
	"errors"
	"fmt"

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
}

// NewSystem builds a host-aware connection. It is local-bus independent: the
// local bus is opened lazily via ConnectLocal so the set_host tool stays usable
// even where no local system bus is available.
func NewSystem(auth auth.AuthKeeper, reg *Registry) *Connection {
	return &Connection{
		reg:      reg,
		auth:     auth,
		rchannel: make(chan string, 1),
	}
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
