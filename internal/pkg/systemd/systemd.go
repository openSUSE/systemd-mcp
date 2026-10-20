package systemd

import (
	"context"
	"errors"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	auth "github.com/openSUSE/systemd-mcp/authkeeper"
	"github.com/openSUSE/systemd-mcp/internal/pkg/util"
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
func (conn *Connection) connectionFor(ctx context.Context, hostName string) (DbusConnection, chan string, bool, error) {
	if conn.reg != nil {
		info, err := conn.reg.Get(hostName)
		if err != nil {
			return nil, nil, false, err
		}
		if !info.IsLocal() {
			remote, err := dialRemote(ctx, info)
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
func (conn *Connection) withConn(ctx context.Context, hostName string, fn func(dc DbusConnection, ch chan string) (*mcp.CallToolResult, any, error)) (*mcp.CallToolResult, any, error) {
	dc, ch, owned, err := conn.connectionFor(ctx, hostName)
	if err != nil {
		return nil, nil, err
	}
	if owned {
		defer dc.Close()
	}
	return fn(dc, ch)
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
