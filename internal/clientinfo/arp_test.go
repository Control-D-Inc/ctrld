package clientinfo

import (
	"sync"
	"testing"
)

func TestArpScan(t *testing.T) {
	a := &arpDiscover{}
	a.scan()

	for _, table := range []*sync.Map{&a.mac, &a.ip} {
		count := 0
		table.Range(func(key, value any) bool {
			count++
			t.Logf("%s => %s", key, value)
			return true
		})
		if count == 0 {
			t.Error("empty result from arp scan")
		}
	}
}
