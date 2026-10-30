package cli

import (
	"bufio"
	"io"
	"maps"
	"slices"
	"strings"
)

// parsePFAnchorNames returns the anchor names that the running ruleset refers to,
// unique and sorted. It takes both pfctl show commands because each one holds half
// of the list: "pfctl -sr" the scrub and filter anchors, "pfctl -sn" the
// translation anchors.
func parsePFAnchorNames(rules, nat io.Reader) []string {
	unique := make(map[string]struct{})
	// A read that stopped early gives a shorter list, and a shorter list reads
	// as an anchor that went away.
	if !collectPFAnchorNames(rules, unique) || !collectPFAnchorNames(nat, unique) {
		return nil
	}
	return slices.Sorted(maps.Keys(unique))
}

// collectPFAnchorNames reports whether it read the whole output.
func collectPFAnchorNames(r io.Reader, into map[string]struct{}) bool {
	if r == nil {
		return true
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		name := pfAnchorNameOf(scanner.Text())
		if name == "" {
			continue
		}
		into[name] = struct{}{}
	}
	return scanner.Err() == nil
}

// pfAnchorNameOf returns the anchor name of one pfctl rule line. The rule verb is
// anchor, nat-anchor, rdr-anchor, scrub-anchor or dummynet-anchor, and the quoted
// name follows it. Every other line, including the merged ALTQ warnings, gives "".
func pfAnchorNameOf(line string) string {
	verb, rest, ok := strings.Cut(strings.TrimSpace(line), " ")
	if !ok || !strings.HasSuffix(verb, "anchor") {
		return ""
	}
	_, quoted, ok := strings.Cut(rest, `"`)
	if !ok {
		return ""
	}
	name, _, ok := strings.Cut(quoted, `"`)
	if !ok {
		return ""
	}
	return name
}

// parsePFStatus reads "pfctl -si" output and reports whether pf runs, with the
// uptime text that pfctl prints beside it.
func parsePFStatus(r io.Reader) (enabled bool, since string) {
	if r == nil {
		return false, ""
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		status, ok := strings.CutPrefix(strings.TrimSpace(scanner.Text()), "Status:")
		if !ok {
			continue
		}
		// pfctl pads the status into a column and prints the debug level next to it.
		status, _, _ = strings.Cut(status, "Debug:")
		state, uptime, _ := strings.Cut(strings.TrimSpace(status), " for ")
		if state != "Enabled" {
			return false, ""
		}
		return true, strings.TrimSpace(uptime)
	}
	// A read that stopped early may have stopped before the status line.
	return false, ""
}
