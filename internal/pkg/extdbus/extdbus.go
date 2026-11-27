// Package extdbus provides a wrapper around go-systemd's dbus.Conn for
// reaching a systemd D-Bus endpoint on a remote host over SSH — the same
// mechanism systemd's own tools (systemctl -H, busctl -H, ...) use.
//
// For each D-Bus bus connection it opens an SSH session channel and execs
// the remote command (by default systemd's companion binary
// "systemd-stdio-bridge"), which bridges the D-Bus system bus to its own
// stdin/stdout. The bytes of the channel are then driven by godbus
// (dbus.NewConn wraps any io.ReadWriteCloser), so the whole remote call
// rides a single SSH channel — no socat / TCP bridge is needed on the
// remote host.
package extdbus

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	systemd "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
	"golang.org/x/crypto/ssh"
)

// Conn is a systemd dbus.Conn whose bytes traverse an SSH session channel
// running systemd-stdio-bridge on the remote host. Call Close when done.
type Conn struct {
	*systemd.Conn

	client *ssh.Client
}

// newBusConn creates a D-Bus connection over rw, performing EXTERNAL auth
// (uid sent as a hex-encoded decimal string, see the D-Bus auth protocol
// spec / dbus.AuthExternal) and the Hello handshake.
func newBusConn(ctx context.Context, rw io.ReadWriteCloser) (*dbus.Conn, error) {
	conn, err := dbus.NewConn(rw, dbus.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("extdbus: new bus conn: %w", err)
	}
	if err := conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Getuid()))}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("extdbus: auth: %w", err)
	}
	if err := conn.Hello(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("extdbus: hello: %w", err)
	}
	return conn, nil
}

// NewSSHConnection dials an SSH connection to sshTarget (host[:port],
// default port 22) and returns a systemd dbus.Conn whose transport is an
// SSH session channel running command on the remote host (default:
// "systemd-stdio-bridge", the same binary "systemctl -H" runs).
//
// go-systemd asks for a fresh bus connection twice — one for method calls
// and one for signal subscription — so every dialBus invocation opens its
// own session/exec channel, kept alive for the lifetime of that D-Bus
// connection. The returned Conn is safe to cancel via the passed context
// (it is forwarded to the D-Bus layer). When done, call Close to release
// the session channels and the SSH session deterministically.
func NewSSHConnection(ctx context.Context, cfg *ssh.ClientConfig, sshTarget, command string) (*Conn, error) {
	if command == "" {
		command = "systemd-stdio-bridge"
	}

	target := sshTarget
	if _, _, err := net.SplitHostPort(target); err != nil {
		target += ":22"
	}

	client, err := ssh.Dial("tcp", target, cfg)
	if err != nil {
		return nil, fmt.Errorf("extdbus: ssh dial %q: %w", target, err)
	}

	c := &Conn{client: client}
	sc, err := systemd.NewConnection(
		func() (*dbus.Conn, error) {
			ch, err := openSessionExec(client, command)
			if err != nil {
				return nil, err
			}
			conn, err := newBusConn(ctx, ch)
			if err != nil {
				_ = ch.Close()
				return nil, err
			}
			return conn, nil
		})
	if err != nil {
		if cerr := c.client.Close(); cerr != nil {
			return nil, fmt.Errorf("extdbus: systemd.NewConnection: %v (close: %v)", err, cerr)
		}
		return nil, fmt.Errorf("extdbus: systemd.NewConnection: %w", err)
	}
	c.Conn = sc
	return c, nil
}

// openSessionExec opens an SSH "session" channel, issues an "exec" request
// for command, and returns the channel (which carries the session's
// stdin/stdout). The exit-status reply is intentionally not awaited; it is
// signalled by the channel closing.
func openSessionExec(client *ssh.Client, command string) (ssh.Channel, error) {
	ch, _, err := client.OpenChannel("session", nil)
	if err != nil {
		return nil, fmt.Errorf("extdbus: open session channel: %w", err)
	}
	if _, err := ch.SendRequest("exec", false, ssh.Marshal(struct {
		Command string
	}{command})); err != nil {
		_ = ch.Close()
		return nil, fmt.Errorf("extdbus: exec request: %w", err)
	}
	return ch, nil
}

// Close closes the D-Bus connection (which closes its underlying session
// channels) and then the SSH session.
func (c *Conn) Close() {
	if sc := c.Conn; sc != nil {
		sc.Close()
	}
	_ = c.client.Close()
}

// Run executes command on the remote host (as the SSH user the connection was
// authenticated as) and returns stdout, stderr and the process exit status.
// It opens a second session channel on the same underlying SSH client that the
// D-Bus bridge rides — no new connection, no new host-key prompt, no new
// authentication — so the same trust / known_hosts / elicitation setup that the
// D-Bus calls rely on applies to the command. Reads are bounded by ctx.
func (c *Conn) Run(ctx context.Context, command string) (string, string, int, error) {
	if c.client == nil {
		return "", "", 0, fmt.Errorf("extdbus: no SSH connection to run %q on", command)
	}
	ch, requests, err := c.client.OpenChannel("session", nil)
	if err != nil {
		return "", "", 0, fmt.Errorf("extdbus: open session channel: %w", err)
	}

	defer ch.Close()

	// consume the channel's requests: capture the process exit-status and ack
	// every request so the remote side never blocks waiting on a reply
	var exitStatus int
	exitDone := make(chan struct{})
	go func() {
		defer close(exitDone)
		for req := range requests {
			if req.Type == "exit-status" && len(req.Payload) >= 4 {
				exitStatus = int(req.Payload[1])
			}
			req.Reply(true, nil)
		}
	}()

	// Send "exec" without waiting for a reply (wantReply=false), matching the
	// D-Bus bridge's openSessionExec. With wantReply=false the library always
	// reports ok=false (see the Channel.SendRequest docs), so only an error
	// signal means the request was rejected; the command's result is observed
	// by draining stdout/stderr below.
	if _, err := ch.SendRequest("exec", false, ssh.Marshal(struct {
		Command string
	}{command})); err != nil {
		return "", "", 0, fmt.Errorf("extdbus: exec request: %w", err)
	}

	var stdout, stderr bytes.Buffer
	cErr := make(chan error, 2)
	go func() { _, err := io.Copy(&stdout, ch); cErr <- err }()
	go func() { _, err := io.Copy(&stderr, ch.Stderr()); cErr <- err }()

	select {
	case e := <-cErr:
		if e != nil && e != io.EOF {
			return stdout.String(), stderr.String(), exitStatus, fmt.Errorf("extdbus: run %q: %w", command, e)
		}
	case <-ctx.Done():
		return stdout.String(), stderr.String(), exitStatus, ctx.Err()
	}
	select {
	case e := <-cErr:
		if e != nil && e != io.EOF {
			return stdout.String(), stderr.String(), exitStatus, fmt.Errorf("extdbus: run %q: %w", command, e)
		}
	case <-ctx.Done():
		return stdout.String(), stderr.String(), exitStatus, ctx.Err()
	}

	// both streams are drained; close the channel on our side and wait for the
	// requests stream to run out so the exit-status has been captured
	_ = ch.CloseWrite()
	select {
	case <-exitDone:
	case <-ctx.Done():
		return stdout.String(), stderr.String(), exitStatus, ctx.Err()
	}

	return stdout.String(), stderr.String(), exitStatus, nil
}
