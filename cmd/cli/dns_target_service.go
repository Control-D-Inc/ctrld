package cli

import (
	"errors"
	"regexp"
	"strings"
)

var targetServiceOrderEntry = regexp.MustCompile(`^\(([1-9][0-9]*|\*)\) (.+)$`)
var targetServiceDevice = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)

// networksetup uses its own service name, which can differ from the Dynamic
// Store's UserDefinedName (for example, iPhone USB versus iPhone).
// Its listing has no UUID, so require exactly one service on the proven
// device, and require that service to be enabled.
func targetNetworkServiceName(output, device string) (string, error) {
	const header = "An asterisk (*) denotes that a network service is disabled."
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 || lines[0] != header || !targetServiceDevice.MatchString(device) {
		return "", errors.New("invalid network service listing")
	}
	seen := make(map[string]bool)
	name, pending := "", ""
	disabled := false
	matches := 0
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if pending == "" {
			m := targetServiceOrderEntry.FindStringSubmatch(line)
			if m == nil {
				return "", errors.New("invalid network service entry")
			}
			pending = m[2]
			disabled = m[1] == "*"
			if strings.HasPrefix(pending, "*") {
				pending = strings.TrimPrefix(pending, "*")
				disabled = true
			}
			if pending == "" || strings.ContainsAny(pending, "\r\n\x00") || seen[strings.ToLower(pending)] {
				return "", errors.New("ambiguous network service name")
			}
			seen[strings.ToLower(pending)] = true
			continue
		}
		if !strings.HasPrefix(line, "(Hardware Port: ") || !strings.HasSuffix(line, ")") {
			return "", errors.New("invalid network service device")
		}
		at := strings.LastIndex(line, ", Device: ")
		if at < 0 {
			return "", errors.New("missing network service device")
		}
		dev := line[at+len(", Device: ") : len(line)-1]
		if dev != "" && !targetServiceDevice.MatchString(dev) {
			return "", errors.New("invalid network device name")
		}
		if dev == device {
			if strings.ContainsAny(pending, "/{}") {
				return "", errors.New("unsafe target service name")
			}
			matches++
			if !disabled {
				name = pending
			}
		}
		pending = ""
	}
	if pending != "" || matches != 1 || name == "" {
		return "", errors.New("network service mapping is missing or ambiguous")
	}
	return name, nil
}
