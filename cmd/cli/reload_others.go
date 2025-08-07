//go:build !windows

package cli

import (
	"os"
	"os/signal"
	"syscall"
)

// notifyReloadSigCh sends reload signal to the channel
func notifyReloadSigCh(ch chan os.Signal) {
	signal.Notify(ch, syscall.SIGUSR1)
}

// sendReloadSignal sends a reload signal to the current process
func (p *prog) sendReloadSignal() error {
	return syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
}
