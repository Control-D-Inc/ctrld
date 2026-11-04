package cli

import (
	"bufio"
	"io"
	"strings"
)

// agentDescriptionKey starts the quoted product name on an ifconfig agent line.
const agentDescriptionKey = `desc:"`

// parseIfconfigAgent returns the owner of a tunnel from "ifconfig -v utunN"
// output. The owner is the description of the first agent line, and a tunnel that
// no network extension owns has no agent line, so the result is "".
func parseIfconfigAgent(r io.Reader) string {
	if r == nil {
		return ""
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "agent ") {
			continue
		}
		_, quoted, ok := strings.Cut(line, agentDescriptionKey)
		if !ok {
			continue
		}
		if description, _, ok := strings.Cut(quoted, `"`); ok && description != "" {
			return description
		}
	}
	// An owner that the read did not reach is not an owner that does not exist.
	return ""
}
