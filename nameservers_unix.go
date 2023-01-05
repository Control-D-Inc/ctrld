//go:build !js && !windows

package ctrld

import (
	"github.com/Control-D-Inc/ctrld/internal/resolvconffile"
)

func nameservers() []string {
	return resolvconffile.NameServersWithPort()
}
