package util

import (
	"os"
	"reflect"
	"testing"
)

func TestHostName(t *testing.T) {
	local, _ := os.Hostname()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty resolves to local hostname", in: "", want: local},
		{name: "localhost resolves to local hostname", in: "localhost", want: local},
		{name: "LOCALHOST is case-insensitive", in: "LOCALHOST", want: local},
		{name: "other host is returned unchanged", in: "remotehost", want: "remotehost"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HostName(tt.in); got != tt.want {
				t.Errorf("HostName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestClearMap(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]interface{}
		want map[string]interface{}
	}{
		{
			name: "empty string value",
			in:   map[string]interface{}{"a": "", "b": "hello"},
			want: map[string]interface{}{"b": "hello"},
		},
		{
			name: "empty string slice value",
			in:   map[string]interface{}{"a": []string{}, "b": "hello"},
			want: map[string]interface{}{"b": "hello"},
		},
		{
			name: "non-empty string slice value",
			in:   map[string]interface{}{"a": []string{"foo"}, "b": "hello"},
			want: map[string]interface{}{"a": []string{"foo"}, "b": "hello"},
		},
		{
			name: "mixed empty values",
			in:   map[string]interface{}{"a": "", "b": []string{}, "c": "hello"},
			want: map[string]interface{}{"c": "hello"},
		},
		{
			name: "no empty values",
			in:   map[string]interface{}{"a": "foo", "b": "bar"},
			want: map[string]interface{}{"a": "foo", "b": "bar"},
		},
		{
			name: "other types",
			in:   map[string]interface{}{"a": 123, "b": "hello"},
			want: map[string]interface{}{"a": 123, "b": "hello"},
		},
		{
			name: "empty map",
			in:   map[string]interface{}{},
			want: map[string]interface{}{},
		},
		{
			name: "nil value",
			in:   map[string]interface{}{"a": nil, "b": "hello"},
			want: map[string]interface{}{"a": nil, "b": "hello"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClearMap(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ClearMap() = %v, want %v", got, tt.want)
			}
		})
	}
}
