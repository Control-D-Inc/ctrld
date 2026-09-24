package cli

import (
	"errors"
	"strings"
)

// networksetup uses its own service name, which can differ from the Dynamic
// Store's UserDefinedName (for example, iPhone USB versus iPhone).
// Its listing has no UUID, so require exactly one service on the proven
// device, and require that service to be enabled. Do not use patchNetIfaceName:
// its first-enabled-match policy cannot prove a unique target for a DNS write.
func targetNetworkServiceName(output, device string) (string, error) {
	if !serviceOrderDeviceName.MatchString(device) {
		return "", errors.New("invalid target device")
	}
	entries, err := parseNetworkServiceOrder(strings.NewReader(output))
	if err != nil {
		return "", err
	}
	seen := make(map[string]bool)
	name := ""
	matches := 0
	for _, entry := range entries {
		key := strings.ToLower(entry.Name)
		if seen[key] {
			return "", errors.New("ambiguous network service name")
		}
		seen[key] = true
		if entry.Device != device {
			continue
		}
		if strings.ContainsAny(entry.Name, "/{}") {
			return "", errors.New("unsafe target service name")
		}
		matches++
		if !entry.Disabled {
			name = entry.Name
		}
	}
	if matches != 1 || name == "" {
		return "", errors.New("network service mapping is missing or ambiguous")
	}
	return name, nil
}
