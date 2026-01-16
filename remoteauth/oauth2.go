package remoteauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

const (
	DefaultProtectedResourceMetadataURI = "/.well-known/oauth-protected-resource"
)

var (
	Audience        = "systemd-mcp-server"
	ScopesSupported = []string{"mcp:read", "mcp:write"} // mcp-user
)

type Oauth2Auth struct {
	KeyFunc keyfunc.Keyfunc // Check oauth2 token func
	JwksUri string
	claims  jwt.MapClaims
	scopes  []string
}

func NewOutah2Auth() Oauth2Auth {
	a := Oauth2Auth{
		claims: make(jwt.MapClaims),
	}
	return a
}

// getJwksUri gets the jwks_uri from the OpenID Provider configuration information.
// See https://openid.net/specs/openid-connect-discovery-1_0.html
func GetJwksURI(issuer string) (string, error) {
	resp, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("failed to get openid-configuration", "status", resp.Status, "url", issuer+"/.well-known/openid-configuration")
		return "", fmt.Errorf("failed to get openid-configuration: %s", resp.Status)
	}

	openIDConfig := struct {
		JwksURI string `json:"jwks_uri"`
	}{}

	err = json.NewDecoder(resp.Body).Decode(&openIDConfig)
	if err != nil {
		return "", err
	}

	return openIDConfig.JwksURI, nil
}

func (a *Oauth2Auth) VerifyJWT(ctx context.Context, tokenString string, _ *http.Request) (*auth.TokenInfo, error) {
	slog.Debug("verifier received token", "value", tokenString)
	token, err := jwt.ParseWithClaims(tokenString, &a.claims, a.KeyFunc.Keyfunc, jwt.WithAudience(Audience),
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Name}))
	if err != nil {
		// Uncomment panic to stop mcp inspector spinning sometimes - it's tedious to kill/restart.
		// Rate limiting middleware is needed to protect against buggy/misbehaving clients.
		// See go-sdk examples/server/rate-limiting/.
		// log.Panicf("err: %v", err)
		slog.Debug("couldn't parse token", "error", err)
		return nil, fmt.Errorf("%v: %w", auth.ErrInvalidToken, err)
	}
	if token.Valid {
		expireTime, err := a.claims.GetExpirationTime()
		if err != nil {
			return nil, fmt.Errorf("%v: %w", auth.ErrInvalidToken, err)
		}
		scopes, ok := a.claims["scope"].(string)
		if !ok {
			return nil, fmt.Errorf("unable to type assert scopes: %w", auth.ErrInvalidToken)
		}
		a.scopes = strings.Split(scopes, " ")
		slog.Debug("scopes", "slice", a.scopes)
		return &auth.TokenInfo{
			Scopes:     strings.Split(scopes, " "),
			Expiration: expireTime.Time,
		}, nil
	}
	a.scopes = []string{}
	return nil, auth.ErrInvalidToken
}

// check if write is authorized via mcp:write
func (a *Oauth2Auth) IsWriteAuthorized() (bool, error) {
	if slices.Contains(a.scopes, "mcp:write") {
		return true, nil
	}
	return false, fmt.Errorf("mcp:write not in scopes: %v", a.scopes)
}

// check if read is authorized via mcp:read
func (a *Oauth2Auth) IsReadAuthorized() (bool, error) {
	if slices.Contains(a.scopes, "mcp:read") {
		return true, nil
	}
	return false, fmt.Errorf("mcp:read not in scopes: %v", a.scopes)
}
