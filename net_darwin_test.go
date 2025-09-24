package ctrld

import (
	"maps"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const listnetworkserviceorderOutput = `
(1) USB 10/100/1000 LAN 2
(Hardware Port: USB 10/100/1000 LAN, Device: en7)

(2) Ethernet
(Hardware Port: Ethernet, Device: en0)

(3) Wi-Fi
(Hardware Port: Wi-Fi, Device: en1)

(4) Bluetooth PAN
(Hardware Port: Bluetooth PAN, Device: en4)

(5) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(6) kernal
(Hardware Port: com.wireguard.macos, Device: )

(7) WS BT
(Hardware Port: com.wireguard.macos, Device: )

(8) ca-001-stg
(Hardware Port: com.wireguard.macos, Device: )

(9) ca-001-stg-2
(Hardware Port: com.wireguard.macos, Device: )

`

func Test_networkServiceName(t *testing.T) {
	tests := []struct {
		ifaceName          string
		networkServiceName string
	}{
		{"en7", "USB 10/100/1000 LAN 2"},
		{"en0", "Ethernet"},
		{"en1", "Wi-Fi"},
		{"en4", "Bluetooth PAN"},
		{"bridge0", "Thunderbolt Bridge"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.ifaceName, func(t *testing.T) {
			t.Parallel()
			name := networkServiceName(tc.ifaceName, strings.NewReader(listnetworkserviceorderOutput))
			assert.Equal(t, tc.networkServiceName, name)
		})
	}
}

const listallhardwareportsOutput = `
Hardware Port: Ethernet Adapter (en6)
Device: en6
Ethernet Address: 3a:3e:fc:1e:ab:41

Hardware Port: Ethernet Adapter (en7)
Device: en7
Ethernet Address: 3a:3e:fc:1e:ab:42

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 36:21:bb:3a:7a:40

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: a0:78:17:68:56:3f

Hardware Port: Thunderbolt 1
Device: en1
Ethernet Address: 36:21:bb:3a:7a:40

Hardware Port: Thunderbolt 2
Device: en2
Ethernet Address: 36:21:bb:3a:7a:44

VLAN Configurations
===================
`

func Test_parseListAllHardwarePorts(t *testing.T) {
	expected := map[string]struct{}{
		"en0":     {},
		"en1":     {},
		"en2":     {},
		"en6":     {},
		"en7":     {},
		"bridge0": {},
	}
	m := parseListAllHardwarePorts(strings.NewReader(listallhardwareportsOutput))
	if !maps.Equal(m, expected) {
		t.Errorf("unexpected output, want: %v, got: %v", expected, m)
	}
}
