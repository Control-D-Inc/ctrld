package clientinfo

import (
	"strings"
	"testing"
)

func Test_ubiosDiscover_storeDevices(t *testing.T) {
	ud := &ubiosDiscover{}
	r := strings.NewReader(`{ "mac": "00:00:00:00:00:01", "name": "device 1" }
{ "mac": "00:00:00:00:00:02", "name": "device 2" }
`)
	if err := ud.storeDevices(r); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		mac      string
		hostname string
	}{
		{"device 1", "00:00:00:00:00:01", "device 1"},
		{"device 2", "00:00:00:00:00:02", "device 2"},
		{"non-existed", "00:00:00:00:00:03", ""},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ud.LookupHostnameByMac(tc.mac); got != tc.hostname {
				t.Errorf("hostname mismatched, want: %q, got: %q", tc.hostname, got)
			}
		})
	}

	// Test for invalid input.
	r = strings.NewReader(`{ "mac": "00:00:00:00:00:01", "name": "device 1"`)
	if err := ud.storeDevices(r); err == nil {
		t.Fatal("expected error, got nil")
	} else {
		t.Log(err)
	}
}
