package main

import (
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
