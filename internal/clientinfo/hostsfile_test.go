package clientinfo

import (
	"strings"
	"testing"
)

func Test_hostsFile_LookupHostnameByIP(t *testing.T) {
	tests := []struct {
		name             string
		ip               string
		hostnames        []string
		expectedHostname string
	}{
		{"ipv4 loopback", "127.0.0.1", []string{ipv4LocalhostName}, ""},
		{"ipv6 loopback", "::1", []string{ipv6LocalhostName, ipv6LoopbackName}, ""},
		{"non-localhost", "::1", []string{"foo"}, "foo"},
		{"multiple hostnames", "::1", []string{ipv4LocalhostName, "foo"}, "foo"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hf := &hostsFile{m: make(map[string][]string)}
			hf.mu.Lock()
			hf.m[tc.ip] = tc.hostnames
			hf.mu.Unlock()
			if got := hf.LookupHostnameByIP(tc.ip); got != tc.expectedHostname {
				t.Errorf("unpexpected result, want: %q, got: %q", tc.expectedHostname, got)
			}
		})
	}
}

func Test_parseHostEntriesConfFromReader(t *testing.T) {
	const content = `local-zone: "localdomain" transparent
local-data-ptr: "127.0.0.1 localhost"
local-data: "localhost A 127.0.0.1"
local-data: "localhost.localdomain A 127.0.0.1"
local-data-ptr: "::1 localhost"
local-data: "localhost AAAA ::1"
local-data: "localhost.localdomain AAAA ::1"
local-data-ptr: "10.0.10.227 OPNsense.localdomain"
local-data: "OPNsense.localdomain A 10.0.10.227"
local-data: "OPNsense A 10.0.10.227"
local-data-ptr: "fe80::5a78:4e29:caa3:f9f7 OPNsense.localdomain"
local-data: "OPNsense.localdomain AAAA fe80::5a78:4e29:caa3:f9f7"
local-data: "OPNsense AAAA fe80::5a78:4e29:caa3:f9f7"
local-data-ptr: "1.1.1.1 banana-party.local.com"
local-data: "banana-party.local.com IN A 1.1.1.1"
local-data-ptr: "1.1.1.1 cheese-land.lan"
local-data: "cheese-land.lan IN A 1.1.1.1"
`
	r := strings.NewReader(content)
	hostsMap := parseHostEntriesConfFromReader(r)
	if len(hostsMap) != 5 {
		t.Fatalf("unexpected number of entries, want 5, got: %d", len(hostsMap))
	}
	for ip, names := range hostsMap {
		switch ip {
		case "1.1.1.1":
			for _, name := range names {
				if name != "banana-party.local.com" && name != "cheese-land.lan" {
					t.Fatalf("unexpected names for 1.1.1.1: %v", names)
				}
			}
		case "10.0.10.227":
			if len(names) != 1 {
				t.Fatalf("unexpected names for 10.0.10.227: %v", names)
			}
			if names[0] != "OPNsense" {
				t.Fatalf("unexpected name: %s", names[0])
			}
		}
	}
}
