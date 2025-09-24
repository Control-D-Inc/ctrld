package ctrld

import (
	"bufio"
	"bytes"
	"io"
	"os/exec"
	"strings"
)

// validInterfaces returns a set of all valid hardware ports.
// TODO: deduplicated with cmd/cli/net_darwin.go in v2.
func validInterfaces() map[string]struct{} {
	b, err := exec.Command("networksetup", "-listallhardwareports").Output()
	if err != nil {
		return nil
	}
	return parseListAllHardwarePorts(bytes.NewReader(b))
}

// parseListAllHardwarePorts parses output of "networksetup -listallhardwareports"
// and returns map presents all hardware ports.
func parseListAllHardwarePorts(r io.Reader) map[string]struct{} {
	m := make(map[string]struct{})
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		after, ok := strings.CutPrefix(line, "Device: ")
		if !ok {
			continue
		}
		m[after] = struct{}{}
	}
	return m
}
