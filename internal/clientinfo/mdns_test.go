package clientinfo

import (
	"strings"
	"testing"
)

func Test_mdns_storeDataFromAvahiBrowseOutput(t *testing.T) {
	const content = `+;wlp0s20f3;IPv6;Foo\032\0402\041;_companion-link._tcp;local
+;wlp0s20f3;IPv4;Foo\032\0402\041;_companion-link._tcp;local
=;wlp0s20f3;IPv6;Foo\032\0402\041;_companion-link._tcp;local;Foo-2.local;192.168.1.123;64842;"rpBA=00:00:00:00:00:01" "rpHI=e6ae2cbbca0e" "rpAD=36566f4d850f" "rpVr=510.71.1" "rpHA=0ddc20fdddc8" "rpFl=0x30000" "rpHN=1d4a03afdefa" "rpMac=0"
=;wlp0s20f3;IPv4;Foo\032\0402\041;_companion-link._tcp;local;Foo-2.local;192.168.1.123;64842;"rpBA=00:00:00:00:00:01" "rpHI=e6ae2cbbca0e" "rpAD=36566f4d850f" "rpVr=510.71.1" "rpHA=0ddc20fdddc8" "rpFl=0x30000" "rpHN=1d4a03afdefa" "rpMac=0"
`
	m := &mdns{}
	m.storeDataFromAvahiBrowseOutput(strings.NewReader(content))
	ip := "192.168.1.123"
	val, loaded := m.name.LoadOrStore(ip, "")
	if !loaded {
		t.Fatal("missing Foo-2 data from mdns table")
	}

	wantHostname := "Foo-2"
	hostname := val.(string)
	if hostname != wantHostname {
		t.Fatalf("unexpected hostname, want: %q, got: %q", wantHostname, hostname)
	}
}
