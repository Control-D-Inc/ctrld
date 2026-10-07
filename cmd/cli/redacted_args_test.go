package cli

import (
	"strings"
	"testing"
)

// The arguments of "ctrld start" go into a debug line; neither the
// provision code nor the resolver uid may reach it, in either flag form.
func TestRedactedArgsRemovesProvisionSecrets(t *testing.T) {
	origOrg, origUID := cdOrg, cdUID
	t.Cleanup(func() { cdOrg, cdUID = origOrg, origUID })
	cdOrg = "org-v1-provisioncode0123"
	cdUID = "resolveruid9/client-name"

	got := redactedArgs([]string{"--cd-org", cdOrg, "--cd=" + cdUID, "-vv", "--log", "C:\\ctrld\\ctrld.log"})

	for _, secret := range []string{cdOrg, cdUID, "resolveruid9", "client-name"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redactedArgs kept %q: %s", secret, got)
		}
	}
	for _, kept := range []string{"--cd-org [redacted]", "--cd=[redacted]", "-vv", "--log"} {
		if !strings.Contains(got, kept) {
			t.Fatalf("redactedArgs lost %q: %s", kept, got)
		}
	}
}
