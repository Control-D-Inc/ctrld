//go:build !windows

package cli

import (
	"github.com/Control-D-Inc/ctrld"
)

// addExtraSplitDnsRule adds split DNS rule if present.
func addExtraSplitDnsRule(_ *ctrld.Config) {}
