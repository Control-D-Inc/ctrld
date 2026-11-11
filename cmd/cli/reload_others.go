//go:build !windows

package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func notifyReloadSigCh(ch chan os.Signal) {
	signal.Notify(ch, syscall.SIGUSR1)
}

func stopNotifyReloadSigCh(ch chan os.Signal) {
	signal.Stop(ch)
}

// sendReloadSignal hands the reload to the run. The signal goes out at once,
// so it needs no context.
func (p *prog) sendReloadSignal(context.Context) error {
	return syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
}
