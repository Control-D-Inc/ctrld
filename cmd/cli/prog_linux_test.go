package cli

import (
	"io"
	"strings"
	"testing"
)

const (
	networkctlUnmanagedOutput = `IDX LINK            TYPE     OPERATIONAL SETUP    
  1 lo              loopback carrier     unmanaged
  2 wlp0s20f3       wlan     routable    unmanaged
  3 tailscale0      none     routable    unmanaged
  4 br-9ac33145e060 bridge   no-carrier  unmanaged
  5 docker0         bridge   no-carrier  unmanaged

5 links listed.
`
	networkctlManagedOutput = `IDX LINK            TYPE     OPERATIONAL SETUP    
  1 lo              loopback carrier     unmanaged
  2 wlp0s20f3       wlan     routable    configured
  3 tailscale0      none     routable    unmanaged
  4 br-9ac33145e060 bridge   no-carrier  unmanaged
  5 docker0         bridge   no-carrier  unmanaged

5 links listed.
`
)

func Test_wantsSystemDNetworkdWaitOnline(t *testing.T) {
	tests := []struct {
		name     string
		r        io.Reader
		required bool
	}{
		{"unmanaged", strings.NewReader(networkctlUnmanagedOutput), false},
		{"managed", strings.NewReader(networkctlManagedOutput), true},
		{"empty", strings.NewReader(""), false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if required := wantsSystemDNetworkdWaitOnline(tc.r); required != tc.required {
				t.Errorf("wants %v got %v", tc.required, required)
			}
		})
	}
}
