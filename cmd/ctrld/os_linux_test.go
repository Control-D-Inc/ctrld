package main

import (
	"reflect"
	"strings"
	"testing"
)

func Test_getDNSBySystemdResolvedFromReader(t *testing.T) {
	r := strings.NewReader(`Link 2 (eth0)
      Current Scopes: DNS
       LLMNR setting: yes
MulticastDNS setting: no
      DNSSEC setting: no
    DNSSEC supported: no
         DNS Servers: 8.8.8.8
                      8.8.4.4`)
	want := []string{"8.8.8.8", "8.8.4.4"}
	ns := getDNSBySystemdResolvedFromReader(r)
	if !reflect.DeepEqual(ns, want) {
		t.Logf("unexpected result, want: %v, got: %v", want, ns)
	}
}
