//go:build unix

package cli

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld/internal/dns/resolvconffile"
)

func oldParseResolvConfNameservers(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Parse the file for "nameserver" lines
	var currentNS []string
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "nameserver") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				currentNS = append(currentNS, parts[1])
			}
		}
	}

	return currentNS, nil
}

// Test_prog_parseResolvConfNameservers tests the parsing of nameservers from resolv.conf content.
// Note: The previous implementation was removed to reduce code duplication and consolidate
// the resolv.conf handling logic into a single unified approach. All resolv.conf parsing
// is now handled by the resolvconffile package, which provides a consistent interface
// for both reading and modifying resolv.conf files across different platforms.
func Test_prog_parseResolvConfNameservers(t *testing.T) {
	oldNss, _ := oldParseResolvConfNameservers(resolvconffile.Path)
	p := &prog{}
	nss, _ := p.parseResolvConfNameservers(resolvconffile.Path)
	slices.Sort(oldNss)
	slices.Sort(nss)
	if !slices.Equal(oldNss, nss) {
		t.Errorf("result mismatched, old: %v, new: %v", oldNss, nss)
	}
	t.Logf("result: %v", nss)
}
