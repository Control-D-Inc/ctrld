package clientinfo

import (
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
