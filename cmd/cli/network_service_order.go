package cli

import (
	"bufio"
	"errors"
	"io"
	"regexp"
	"strings"
)

// maxNetworksetupLine bounds one line, so one token fills no memory.
const maxNetworksetupLine = 64 * 1024

var serviceOrderEntry = regexp.MustCompile(`^\(([1-9][0-9]*|\*)\) (.+)$`)
var serviceOrderDeviceName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)

type networkServiceEntry struct {
	Name, Device string
	Disabled     bool
}

// scanNetworksetup reads the output line by line under a bounded buffer.
func scanNetworksetup(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, maxNetworksetupLine)
	return scanner
}

// parseNetworkServiceOrder decodes networksetup -listnetworkserviceorder.
// Selection policy belongs to the caller: retain disabled and duplicate-device
// entries so a DNS writer can reject mappings a first-match reader accepts.
func parseNetworkServiceOrder(r io.Reader) ([]networkServiceEntry, error) {
	const header = "An asterisk (*) denotes that a network service is disabled."
	scanner := scanNetworksetup(r)
	var entries []networkServiceEntry
	var pending *networkServiceEntry
	headerSeen := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !headerSeen {
			if strings.TrimSpace(line) != header {
				return nil, errors.New("invalid network service listing")
			}
			headerSeen = true
			continue
		}
		if pending == nil {
			m := serviceOrderEntry.FindStringSubmatch(line)
			if m == nil || strings.ContainsAny(m[2], "\r\n\x00") {
				return nil, errors.New("invalid network service entry")
			}
			// Only the index marks a disabled service. An enabled name may
			// itself start with an asterisk; preserve it and its whitespace.
			pending = &networkServiceEntry{Name: m[2], Disabled: m[1] == "*"}
			continue
		}
		if !strings.HasPrefix(line, "(Hardware Port: ") || !strings.HasSuffix(line, ")") {
			return nil, errors.New("invalid network service device")
		}
		at := strings.LastIndex(line, ", Device: ")
		if at < 0 {
			return nil, errors.New("missing network service device")
		}
		device := line[at+len(", Device: ") : len(line)-1]
		if device != "" && !serviceOrderDeviceName.MatchString(device) {
			return nil, errors.New("invalid network device name")
		}
		pending.Device = device
		entries = append(entries, *pending)
		pending = nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !headerSeen || pending != nil {
		return nil, errors.New("incomplete network service listing")
	}
	return entries, nil
}

// serviceNamesByDevice keeps the first enabled service on each device for
// interface-name lookup and hardware-port metadata, not DNS-target admission.
func serviceNamesByDevice(r io.Reader) map[string]string {
	entries, err := parseNetworkServiceOrder(r)
	if err != nil {
		return nil
	}
	names := make(map[string]string)
	for _, entry := range entries {
		if entry.Disabled || entry.Device == "" {
			continue
		}
		if _, seen := names[entry.Device]; !seen {
			names[entry.Device] = entry.Name
		}
	}
	return names
}
