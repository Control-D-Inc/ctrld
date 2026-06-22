package cli

import "testing"

func TestIsExplicitInterceptListener(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		port int
		want bool
	}{
		{name: "empty", ip: "", port: 0, want: false},
		{name: "wildcard", ip: "0.0.0.0", port: 53, want: false},
		{name: "zero port", ip: "127.0.0.1", port: 0, want: false},
		{name: "default intercept listener", ip: "127.0.0.1", port: 53, want: false},
		{name: "fallback port explicit", ip: "127.0.0.1", port: 5354, want: true},
		{name: "custom loopback explicit", ip: "127.0.0.2", port: 53, want: true},
		{name: "custom address explicit", ip: "192.0.2.10", port: 53, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExplicitInterceptListener(tt.ip, tt.port); got != tt.want {
				t.Fatalf("isExplicitInterceptListener(%q, %d) = %v, want %v", tt.ip, tt.port, got, tt.want)
			}
		})
	}
}
