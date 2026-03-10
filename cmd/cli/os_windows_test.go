package cli

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func Test_currentStaticDNS(t *testing.T) {
	iface, err := net.InterfaceByName(defaultIfaceName())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	staticDns, err := currentStaticDNS(iface)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Using Windows API takes: %d", time.Since(start).Milliseconds())

	start = time.Now()
	staticDnsPowershell, err := currentStaticDnsPowershell(iface)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Using Powershell takes: %d", time.Since(start).Milliseconds())

	slices.Sort(staticDns)
	slices.Sort(staticDnsPowershell)
	if !slices.Equal(staticDns, staticDnsPowershell) {
		t.Fatalf("result mismatch, want: %v, got: %v", staticDnsPowershell, staticDns)
	}
}

func currentStaticDnsPowershell(iface *net.Interface) ([]string, error) {
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		return nil, err
	}
	guid, err := luid.GUID()
	if err != nil {
		return nil, err
	}
	var ns []string
	for _, path := range []string{"HKLM:\\" + v4InterfaceKeyPathFormat, "HKLM:\\" + v6InterfaceKeyPathFormat} {
		interfaceKeyPath := path + guid.String()
		found := false
		for _, key := range []string{"NameServer", "ProfileNameServer"} {
			if found {
				continue
			}
			cmd := fmt.Sprintf(`Get-ItemPropertyValue -Path "%s" -Name "%s"`, interfaceKeyPath, key)
			out, err := powershell(cmd)
			if err == nil && len(out) > 0 {
				found = true
				for _, e := range strings.Split(string(out), ",") {
					ns = append(ns, strings.TrimRight(e, "\x00"))
				}
			}
		}
	}
	return ns, nil
}

// powershell runs the given powershell command.
func powershell(cmd string) ([]byte, error) {
	out, err := exec.Command("powershell", "-Command", cmd).CombinedOutput()
	return bytes.TrimSpace(out), err
}
