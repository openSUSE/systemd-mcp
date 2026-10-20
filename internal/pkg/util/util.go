package util

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/alpkeskin/gotoon"
)

// HostName resolves a host argument to a concrete hostname.
// An empty value and "localhost" are synonyms for the local machine, so they
// are replaced with os.Hostname(). Any other value is returned unchanged.
func HostName(host string) string {
	if host == "" || strings.EqualFold(host, "localhost") {
		if h, err := os.Hostname(); err == nil && h != "" {
			return h
		}
		return "localhost"
	}
	return host
}

// LocalHostName returns the hostname of the local machine, falling back to
// "localhost" if it cannot be determined.
func LocalHostName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "localhost"
}

// EncodeWithHost returns value encoded alongside a top-level "host" field that
// carries the local machine's hostname. value is normalized to a JSON object
// first (the same representation the toon encoder produces for structs), so
// the output shape is identical for both json and toon encoders.
func EncodeWithHost(enc OutputEncoding, value any) ([]byte, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	m["host"] = LocalHostName()
	return enc.Encode(m)
}

/*
cleans a map from emty strng or string slices with length 0
*/
func ClearMap(in map[string]interface{}) map[string]interface{} {
	for key, elem := range in {
		if str, ok := elem.(string); ok {
			if str == "" {
				delete(in, key)
			}
		}
		if strSlc, ok := elem.([]string); ok {
			if len(strSlc) == 0 {
				delete(in, key)
			}
		}
		if anySlc, ok := elem.([]interface{}); ok {
			if len(anySlc) == 0 {
				delete(in, key)
			}
		}
	}
	return in
}

// Use a drop in marshaller which outputs toon via gotoon or standard json
type OutputEncoding struct {
	useToon bool
}

func (enc *OutputEncoding) UseToon() {
	enc.useToon = true
}

func (enc *OutputEncoding) IsToon() bool {
	return enc.useToon
}

func (enc OutputEncoding) Encode(input any) (out []byte, err error) {
	if enc.useToon {
		outStr, err := gotoon.Encode(input)
		return []byte(outStr), err
	} else {
		return json.Marshal(input)
	}
}
