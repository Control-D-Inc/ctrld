package clientinfo

import (
	"strings"
	"sync"
	"testing"
)

func Test_ndpDiscover_scanUnix(t *testing.T) {
	r := strings.NewReader(`Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs
2405:4802:1f90:fda0:1459:ec89:523d:3583 00:0:00:0:00:01      en0 permanent R
2405:4802:1f90:fda0:186b:c54a:1370:c196 (incomplete)         en0 expired   N
2405:4802:1f90:fda0:88de:14ef:6a8c:579a 00:0:00:0:00:02      en0 permanent R
fe80::1%lo0                             (incomplete)         lo0 permanent R
`)
	nd := &ndpDiscover{}
	nd.scanUnix(r)

	for _, m := range []*sync.Map{&nd.mac, &nd.ip} {
		count := 0
		m.Range(func(key, value any) bool {
			count++
			return true
		})
		if count != 2 {
			t.Errorf("unexpected count, want 2, got: %d", count)
		}
	}
}

func Test_ndpDiscover_scanWindows(t *testing.T) {
	r := strings.NewReader(`Interface 14: Wi-Fi


Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
2405:4802:1f90:fda0:ffff:ffff:ffff:ff88       00-00-00-00-00-00  Unreachable
fe80::1                                       60-57-47-21-dd-00  Reachable (Router)
fe80::6257:47ff:fe21:dd00                     60-57-47-21-dd-00  Reachable (Router)
ff02::1                                       33-33-00-00-00-01  Permanent
ff02::2                                       33-33-00-00-00-02  Permanent
ff02::c                                       33-33-00-00-00-0c  Permanent
`)
	nd := &ndpDiscover{}
	nd.scanWindows(r)

	count := 0
	expectedCount := 5
	nd.mac.Range(func(key, value any) bool {
		count++
		return true
	})
	// There are 2 entries for 60-57-47-21-dd-00 in the table, but (*ndpDiscover).saveInfo
	// only saves the last one, that's why the expected count number is 5.
	if count != expectedCount {
		t.Errorf("unexpected count, want %d, got: %d", expectedCount, count)
	}

	count = 0
	nd.ip.Range(func(key, value any) bool {
		count++
		return true
	})
	if count != expectedCount {
		t.Errorf("unexpected count, want %d, got: %d", expectedCount, count)
	}
}
