//go:build unix

package ctrld

import "github.com/Control-D-Inc/ctrld/internal/resolvconffile"

func nameserversFromResolvconf() []string {
	return resolvconffile.NameServers("")
}
