package authkeeper

import (
	"context"
	"log/slog"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	godbus "github.com/godbus/dbus/v5"
	"github.com/openSUSE/systemd-mcp/dbus"
	"github.com/openSUSE/systemd-mcp/remoteauth"
)

// IsDBusNameTaken checks if the dbus name is already taken.
func IsDBusNameTaken(dbusName string) (bool, error) {
	return dbus.IsDBusNameTaken(dbusName)
}

type AuthKeeper struct {
	Dbus         *dbus.DbusAuth
	Oauth2       *remoteauth.Oauth2Auth
	Timeout      uint32
	ReadAllowed  bool
	WriteAllowed bool
	context      context.Context
}

func (a *AuthKeeper) Mode() AuthMode {
	// this shouldn't happen
	if a.Dbus != nil && a.Oauth2 != nil {
		slog.Warn("ouath2 and dbus/polkit authentication defined", "auth", "noauth")
		return noauth
	}
	if a.Dbus != nil {
		return polkit
	}
	if a.Oauth2 != nil {
		return oauth2
	}
	return noauth
}

type AuthMode uint

const (
	noauth AuthMode = iota
	oauth2
	polkit
)

// setup the dbus authorization call back.
func NewPolkitAuth(dbusName, dbusPath string) (*AuthKeeper, error) {
	d, err := dbus.SetupDBus(dbusName, dbusPath)
	if err != nil {
		return nil, err
	}
	return &AuthKeeper{
		Dbus: d,
	}, nil
}

// no auth at all
func NewNoAuth() (*AuthKeeper, error) {
	a := new(AuthKeeper)
	a.ReadAllowed = true
	a.WriteAllowed = true
	return a, nil
}

// remote auth with oauth2
func NewOauth(controller string) (*AuthKeeper, error) {
	if !strings.HasPrefix(controller, "http") {
		controller = "http://" + controller
	}
	a := new(AuthKeeper)
	jwksURI, err := remoteauth.GetJwksURI(controller)
	if err != nil {
		return a, err
	}
	a.context = context.Background()
	keyf, err := keyfunc.NewDefaultCtx(a.context, []string{jwksURI})
	if err != nil {
		return a, err
	}
	a.Oauth2 = &remoteauth.Oauth2Auth{KeyFunc: keyf}
	a.Oauth2.JwksUri = jwksURI
	return a, nil
}

func (a *AuthKeeper) Close() error {
	if a.Dbus != nil && a.Dbus.Conn != nil {
		return a.Dbus.Conn.Close()
	}
	return nil
}

// Delegate methods to Dbus

func (a *AuthKeeper) IsReadAuthorized() (bool, error) {
	switch a.Mode() {
	case oauth2:
		return a.Oauth2.IsReadAuthorized()
	case polkit:
		return a.Dbus.IsReadAuthorized()
	default:
		return a.ReadAllowed, nil
	}
}

func (a *AuthKeeper) IsWriteAuthorized(systemdPermission string) (bool, error) {
	switch a.Mode() {
	case oauth2:
		return a.Oauth2.IsWriteAuthorized()
	case polkit:
		return a.Dbus.IsWriteAuthorized("")
	default:
		return a.WriteAllowed, nil
	}
}

func (a *AuthKeeper) Deauthorize() *godbus.Error {
	if a.Dbus == nil {
		return nil
	}
	return a.Dbus.Deauthorize()
}
