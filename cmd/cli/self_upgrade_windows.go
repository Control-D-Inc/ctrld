package cli

import (
	"syscall"
)

// From: https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags?redirectedfrom=MSDN

// SYSCALL_CREATE_NO_WINDOW set flag to run process without a console window.
const SYSCALL_CREATE_NO_WINDOW = 0x08000000

// sysProcAttrForSelfUpgrade returns *syscall.SysProcAttr instance for running self-upgrade command.
func sysProcAttrForSelfUpgrade() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | SYSCALL_CREATE_NO_WINDOW,
		HideWindow:    true,
	}
}
