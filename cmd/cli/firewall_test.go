package cli

import "testing"

func TestExtractHostFromEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "https URL", endpoint: "https://dns.controld.com/abcdef", want: "dns.controld.com"},
		{name: "URL with userinfo", endpoint: "https://user:pass@dns.controld.com/abcdef", want: "dns.controld.com"},
		{name: "URL with IPv6 literal", endpoint: "https://[2606:4700:4700::1111]:443/dns-query", want: "2606:4700:4700::1111"},
		{name: "host port", endpoint: "1.2.3.4:53", want: "1.2.3.4"},
		{name: "bare IP", endpoint: "1.2.3.4", want: "1.2.3.4"},
		{name: "DNS stamp", endpoint: "sdns://AgcAAAAAAAAAAA", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractHostFromEndpoint(tt.endpoint); got != tt.want {
				t.Fatalf("extractHostFromEndpoint(%q) = %q, want %q", tt.endpoint, got, tt.want)
			}
		})
	}
}
