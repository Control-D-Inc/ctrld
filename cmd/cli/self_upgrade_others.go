//go:build !windows

package cli

import (
	"syscall"
)

// sysProcAttrForSelfUpgrade returns *syscall.SysProcAttr instance for running self-upgrade command.
func sysProcAttrForSelfUpgrade() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
