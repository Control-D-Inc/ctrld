//go:build unix

package ctrld

import (
	"net/netip"
	"testing"
)

func Test_localNameservers(t *testing.T) {
	loopbackIPs := []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("::1"),
	}
	regularIPs := []netip.Addr{
		netip.MustParseAddr("192.168.1.100"),
		netip.MustParseAddr("10.0.0.5"),
	}

	tests := []struct {
		name       string
		nss        []string
		regularIPs []netip.Addr
		loopbackIPs []netip.Addr
		want       []string
	}{
		{
			name:        "filters loopback IPv4",
			nss:         []string{"127.0.0.1", "8.8.8.8"},
			regularIPs:  nil,
			loopbackIPs: loopbackIPs,
			want:        []string{"8.8.8.8"},
		},
		{
			name:        "filters loopback IPv6",
			nss:         []string{"::1", "1.1.1.1"},
			regularIPs:  nil,
			loopbackIPs: loopbackIPs,
			want:        []string{"1.1.1.1"},
		},
		{
			name:        "filters local machine IPs",
			nss:         []string{"192.168.1.100", "8.8.4.4"},
			regularIPs:  regularIPs,
			loopbackIPs: nil,
			want:        []string{"8.8.4.4"},
		},
		{
			name:        "filters both loopback and local IPs",
			nss:         []string{"127.0.0.1", "192.168.1.100", "8.8.8.8"},
			regularIPs:  regularIPs,
			loopbackIPs: loopbackIPs,
			want:        []string{"8.8.8.8"},
		},
		{
			name:        "deduplicates results",
			nss:         []string{"8.8.8.8", "8.8.8.8", "1.1.1.1"},
			regularIPs:  regularIPs,
			loopbackIPs: loopbackIPs,
			want:        []string{"8.8.8.8", "1.1.1.1"},
		},
		{
			name:        "all filtered returns nil",
			nss:         []string{"127.0.0.1", "::1", "192.168.1.100"},
			regularIPs:  regularIPs,
			loopbackIPs: loopbackIPs,
			want:        nil,
		},
		{
			name:        "empty input returns nil",
			nss:         nil,
			regularIPs:  regularIPs,
			loopbackIPs: loopbackIPs,
			want:        nil,
		},
		{
			name:        "skips unparseable entries",
			nss:         []string{"not-an-ip", "8.8.8.8"},
			regularIPs:  regularIPs,
			loopbackIPs: loopbackIPs,
			want:        []string{"8.8.8.8"},
		},
		{
			name:        "no local IPs filters nothing",
			nss:         []string{"8.8.8.8", "1.1.1.1"},
			regularIPs:  nil,
			loopbackIPs: nil,
			want:        []string{"8.8.8.8", "1.1.1.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := localNameservers(tt.nss, tt.regularIPs, tt.loopbackIPs)
			if len(got) != len(tt.want) {
				t.Fatalf("localNameservers() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("localNameservers()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
