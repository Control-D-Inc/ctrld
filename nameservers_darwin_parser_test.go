package ctrld

import (
	"slices"
	"testing"
)

func TestParseDHCPOptionNameservers(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   []string
	}{
		{"single", "192.168.10.1\n", []string{"192.168.10.1"}},
		{"multiple", "192.168.10.1\n1.1.1.1\n", []string{"192.168.10.1", "1.1.1.1"}},
		{"deduplicate and reject invalid", "192.168.10.1 999.1.1.1 192.168.10.1", []string{"192.168.10.1"}},
		{"empty", "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDHCPOptionNameservers([]byte(tc.output)); !slices.Equal(got, tc.want) {
				t.Fatalf("parseDHCPOptionNameservers() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseDHCPPacketNameservers(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   []string
	}{
		{
			name: "macos singular ip_mult",
			output: `op = BOOTREPLY
` +
				`yiaddr = 192.168.10.155
` +
				`domain_name_server (ip_mult): {192.168.10.1, 1.1.1.1}
` +
				`server_identifier (ip): 192.168.10.1
`,
			want: []string{"192.168.10.1", "1.1.1.1"},
		},
		{
			name:   "legacy plural equals",
			output: "domain_name_servers = 192.168.1.1 8.8.8.8;\n",
			want:   []string{"192.168.1.1", "8.8.8.8"},
		},
		{
			name:   "packet addresses without option are ignored",
			output: "yiaddr = 192.168.10.155\nserver_identifier (ip): 192.168.10.1\n",
			want:   nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDHCPPacketNameservers([]byte(tc.output)); !slices.Equal(got, tc.want) {
				t.Fatalf("parseDHCPPacketNameservers() = %v, want %v", got, tc.want)
			}
		})
	}
}
