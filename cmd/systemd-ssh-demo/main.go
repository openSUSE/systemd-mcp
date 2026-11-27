// Command systemd-ssh-demo talks to systemd's D-Bus API on a remote host
// over SSH (see the extdbus package). It uses the same mechanism systemd's
// own tools do: each D-Bus bus connection runs the remote
// "systemd-stdio-bridge" binary in an SSH session and pipes the bus bytes
// through the channel — no socat / TCP bridge is needed on the remote host.
//
// Usage:
//
//	systemd-ssh-demo -target user@host:22 list
//	systemd-ssh-demo -target user@host:22 status systemd-journald
//	systemd-ssh-demo -target user@host:22 start foo.service
//	systemd-ssh-demo -target user@host:22 stop foo.service
//
// The remote host must have "systemd-stdio-bridge" in PATH (it ships with
// systemd; override the exact command with -remote-cmd).
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/openSUSE/systemd-mcp/internal/pkg/extdbus"
)

func main() {
	var (
		target   = flag.String("target", "", "ssh target host[:port] (default port 22); username via -user")
		user     = flag.String("user", os.Getenv("USER"), "ssh user")
		key      = flag.String("key", "", "ssh private key file")
		known    = flag.String("known-hosts", "", "ssh known_hosts file")
		insecure = flag.Bool("insecure", false, "accept any ssh host key (demo/testing only)")
		remote   = flag.String("remote-cmd", "systemd-stdio-bridge", "command to exec on the remote host")
		timeout  = flag.Duration("timeout", 15*time.Second, "overall operation timeout")
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s list | status <unit> | start <unit> | stop <unit>\n\nflags:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "error: -target is required")
		flag.Usage()
		os.Exit(2)
	}
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "error: a command is required (list, status, start, stop)")
		os.Exit(2)
	}
	sshCmd := flag.Arg(0)
	unit := ""
	if flag.NArg() > 1 {
		unit = flag.Arg(1)
	}
	if sshCmd != "list" && unit == "" {
		fmt.Fprintf(os.Stderr, "error: command %q needs a unit name\n", sshCmd)
		os.Exit(2)
	}
	// The username travels in ssh.ClientConfig.User (set by sshConfig), so
	// the target here must be a bare host[:port] — prepending "user@" would
	// make ssh.Dial treat it as the DNS hostname and fail with "no such host".
	if !hasPort(*target) {
		*target += ":22"
	}

	cfg, err := sshConfig(*user, *key, *known, *insecure)
	if err != nil {
		die(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := extdbus.NewSSHConnection(ctx, cfg, *target, *remote)
	if err != nil {
		die(err)
	}
	defer conn.Close()

	switch sshCmd {
	case "list":
		units, err := conn.ListUnits()
		if err != nil {
			die(err)
		}
		fmt.Printf("%-40s %-8s %-10s %s\n", "NAME", "ACTIVE", "SUB", "DESCRIPTION")
		for _, u := range units {
			fmt.Printf("%-40s %-8s %-10s %s\n", u.Name, u.ActiveState, u.SubState, u.Description)
		}
	case "status":
		props, err := conn.GetUnitProperties(unit)
		if err != nil {
			die(err)
		}
		for _, k := range []string{"LoadState", "ActiveState", "SubState", "Description", "MainPID"} {
			if v, ok := props[k]; ok {
				fmt.Printf("%-16s %v\n", k+":", v)
			}
		}
	case "start", "stop":
		ch := make(chan string, 1)
		var (
			id  int
			err error
		)
		if sshCmd == "start" {
			id, err = conn.StartUnit(unit, "replace", ch)
		} else {
			id, err = conn.StopUnit(unit, "replace", ch)
		}
		if err != nil {
			die(err)
		}
		select {
		case result := <-ch:
			fmt.Printf("job %d finished: %s\n", id, result)
		case <-ctx.Done():
			die(ctx.Err())
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", sshCmd)
		os.Exit(2)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func hasPort(addr string) bool {
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}

func sshConfig(user, key, knownHosts string, insecure bool) (*ssh.ClientConfig, error) {
	cfg := &ssh.ClientConfig{
		User:    user,
		Timeout: 10 * time.Second,
	}

	var signers []ssh.Signer

	// 1. Ask the local ssh-agent (SSH_AUTH_SOCK) for its keys first. The
	//    agent already holds unlocked keys, so it also serves passphrase-
	//    protected keys that ssh.ParsePrivateKey cannot decode.
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			if as, err := agent.NewClient(conn).Signers(); err != nil {
				fmt.Fprintf(os.Stderr, "warning: ssh-agent signers: %v\n", err)
			} else {
				signers = append(signers, as...)
			}
		}
	}

	// 2. Parse an explicitly provided key (or a conventional on-disk key)
	//    and add it. Failures here are non-fatal so they never mask an
	//    agent-provided signer; a problematic file key is simply skipped.
	if key == "" && !insecure {
		if d := defaultKeyPath(); d != "" {
			key = d
		}
	}
	if key != "" {
		if raw, err := os.ReadFile(path.Clean(key)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: can't read ssh key %q: %v\n", key, err)
		} else if signer, err := ssh.ParsePrivateKey(raw); err != nil {
			fmt.Fprintf(os.Stderr, "warning: can't parse ssh key %q: %v (passphrase-protected keys are only usable via ssh-agent / ssh-add)\n", key, err)
		} else {
			signers = append(signers, signer)
		}
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("no ssh key available: provide an unencrypted -key or run ssh-add (passphrase-protected keys must be loaded into the agent)")
	}
	cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signers...)}

	if insecure {
		cfg.HostKeyCallback = ssh.InsecureIgnoreHostKey() //nolint:gosec // demo only, flagged on stderr
		fmt.Fprintln(os.Stderr, "warning: -insecure disables SSH host key verification (demo/testing only)")
	} else {
		if knownHosts == "" {
			if d := knownHostsPath(); d != "" {
				knownHosts = d
			}
		}
		if knownHosts == "" {
			return nil, fmt.Errorf("-known-hosts is required unless -insecure is set")
		}
		callback, err := knownhosts.New(knownHosts)
		if err != nil {
			return nil, fmt.Errorf("parse known_hosts: %w", err)
		}
		cfg.HostKeyCallback = callback
	}
	return cfg, nil
}

func defaultKeyPath() string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return ""
	}
	for _, f := range []string{"id_ed25519", "id_rsa"} {
		p := path.Join(home, ".ssh", f)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func knownHostsPath() string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return ""
	}
	p := path.Join(home, ".ssh", "known_hosts")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}
