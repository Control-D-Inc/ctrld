//go:build unix

package cli

import (
	"tailscale.com/util/dnsname"

	"github.com/Control-D-Inc/ctrld/internal/resolvconffile"
)

// searchDomains returns the current search domains config.
func searchDomains() ([]dnsname.FQDN, error) {
	return resolvconffile.SearchDomains()
}
