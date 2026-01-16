package remoteauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetJwksURI(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/openid-configuration" {
				t.Errorf("expected path /.well-known/openid-configuration, got %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"jwks_uri": "https://example.com/jwks"}`))
		}))
		defer server.Close()

		uri, err := GetJwksURI(server.URL)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if uri != "https://example.com/jwks" {
			t.Errorf("expected https://example.com/jwks, got %s", uri)
		}
	})

	t.Run("not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		_, err := GetJwksURI(server.URL)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectedErr := "failed to get openid-configuration: 404 Not Found"
		if err.Error() != expectedErr {
			t.Errorf("expected %s, got %v", expectedErr, err)
		}
	})

	t.Run("internal server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		_, err := GetJwksURI(server.URL)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectedErr := "failed to get openid-configuration: 500 Internal Server Error"
		if err.Error() != expectedErr {
			t.Errorf("expected %s, got %v", expectedErr, err)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`invalid json`))
		}))
		defer server.Close()

		_, err := GetJwksURI(server.URL)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
