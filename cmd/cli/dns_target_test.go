package cli

import (
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

func TestHasIPv4DNS(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want bool
	}{
		{"empty", nil, false},
		{"ipv4", []string{"8.8.8.8"}, true},
		{"ipv4 with port", []string{"192.168.1.1:53"}, true},
		{"loopback counts", []string{"127.0.0.1"}, true},
		{"ipv6 only", []string{"2001:4860:4860::8888"}, false},
		{"ipv6 with port", []string{"[2001:4860:4860::8888]:53"}, false},
		{"mixed", []string{"2001:4860:4860::8888", "9.9.9.9"}, true},
		{"garbage ignored", []string{"not-an-ip", ""}, false},
		{"garbage plus v4", []string{"not-an-ip", "1.1.1.1"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasIPv4DNS(tc.in); got != tc.want {
				t.Errorf("hasIPv4DNS(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNeedsInterceptDNSTarget(t *testing.T) {
	tests := []struct {
		name               string
		static, discovered []string
		want               bool
	}{
		{"no dns at all", nil, nil, true},
		{"ipv6-only tether (464XLAT, issue #533)", nil, []string{"2605:8d80::1"}, true},
		{"static v4 present", []string{"1.1.1.1"}, nil, false},
		{"discovered v4 present", nil, []string{"192.168.1.1:53"}, false},
		{"existing ctrld target satisfies", []string{"127.0.0.1"}, nil, false},
		{"ipv6 static, v4 discovered", []string{"2001:db8::1"}, []string{"10.0.0.1"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsInterceptDNSTarget(tc.static, tc.discovered); got != tc.want {
				t.Errorf("needsInterceptDNSTarget(%v, %v) = %v, want %v", tc.static, tc.discovered, got, tc.want)
			}
		})
	}
}

func TestIsInterceptDNSTargetOnly(t *testing.T) {
	tests := []struct {
		name   string
		in     []string
		target string
		want   bool
	}{
		{"exactly ours (direct listener)", []string{"127.0.0.1"}, "127.0.0.1", true},
		{"exactly ours (rdr target)", []string{"127.0.0.53"}, "127.0.0.53", true},
		{"empty list", nil, "127.0.0.1", false},
		{"empty target never matches", []string{"127.0.0.1"}, "", false},
		{"ours plus user entry", []string{"127.0.0.1", "1.1.1.1"}, "127.0.0.1", false},
		{"user entry only", []string{"1.1.1.1"}, "127.0.0.1", false},
		{"different loopback than ours", []string{"127.0.0.53"}, "127.0.0.1", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isInterceptDNSTargetOnly(tc.in, tc.target); got != tc.want {
				t.Errorf("isInterceptDNSTargetOnly(%v, %q) = %v, want %v", tc.in, tc.target, got, tc.want)
			}
		})
	}
}

func TestInterceptDNSTargetValue(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		port int
		want string
	}{
		{"default direct listener :53", "127.0.0.1", 53, "127.0.0.1"},
		{"custom loopback listener :53", "127.0.0.2", 53, "127.0.0.2"},
		{"non-53 port uses rdr target", "127.0.0.1", 5354, "127.0.0.53"},
		{"listener on rdr target with non-53 port", "127.0.0.53", 5354, "127.0.0.54"},
		{"wildcard ip :53 falls back to loopback", "0.0.0.0", 53, "127.0.0.1"},
		{"wildcard ip non-53 uses rdr target", "0.0.0.0", 5354, "127.0.0.53"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &prog{cfg: &ctrld.Config{
				Listener: map[string]*ctrld.ListenerConfig{
					"0": {IP: tc.ip, Port: tc.port},
				},
			}}
			if got := p.interceptDNSTargetValue(); got != tc.want {
				t.Errorf("interceptDNSTargetValue() with listener %s:%d = %q, want %q", tc.ip, tc.port, got, tc.want)
			}
		})
	}
}

func TestInterceptDNSTargetValue_NoListener(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{}}
	if got := p.interceptDNSTargetValue(); got != "127.0.0.1" {
		t.Errorf("interceptDNSTargetValue() with no listener = %q, want 127.0.0.1", got)
	}
}
