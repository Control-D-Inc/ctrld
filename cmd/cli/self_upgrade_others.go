//go:build !windows

package cli

import (
	"syscall"
)

// sysProcAttrForDetachedChildProcess returns *syscall.SysProcAttr instance for running a detached child command.
func sysProcAttrForDetachedChildProcess() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
