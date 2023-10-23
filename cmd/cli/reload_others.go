//go:build !windows

package cli

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyReloadSigCh(ch chan os.Signal) {
	signal.Notify(ch, syscall.SIGUSR1)
}

func (p *prog) sendReloadSignal() error {
	return syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
}
