package cli

import (
	"bufio"
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"
)

func Test_validInterfaces(t *testing.T) {
	verbose = 3
	initConsoleLogging()
	start := time.Now()
	ifaces := validInterfaces()
	t.Logf("Using Windows API takes: %d", time.Since(start).Milliseconds())

	start = time.Now()
	ifacesPowershell := validInterfacesPowershell()
	t.Logf("Using Powershell takes: %d", time.Since(start).Milliseconds())

	slices.Sort(ifaces)
	slices.Sort(ifacesPowershell)
	if !slices.Equal(ifaces, ifacesPowershell) {
		t.Fatalf("result mismatch, want: %v, got: %v", ifacesPowershell, ifaces)
	}
}

func validInterfacesPowershell() []string {
	out, err := powershell("Get-NetAdapter -Physical | Select-Object -ExpandProperty Name")
	if err != nil {
		return nil
	}
	var res []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		ifaceName := strings.TrimSpace(scanner.Text())
		res = append(res, ifaceName)
	}
	return res
}
