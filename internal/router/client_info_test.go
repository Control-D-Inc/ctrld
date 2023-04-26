package router

import "testing"

func Test_normalizeIP(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"v4", "127.0.0.1", "127.0.0.1"},
		{"v4 with index", "127.0.0.1%lo", "127.0.0.1"},
		{"v6", "fe80::1", "fe80::1"},
		{"v6 with index", "fe80::1%22002", "fe80::1"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeIP(tc.in); got != tc.want {
				t.Errorf("normalizeIP() = %v, want %v", got, tc.want)
			}
		})
	}
}
