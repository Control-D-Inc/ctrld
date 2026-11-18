package cli

import (
	"context"
	"errors"
	"os"
	"time"
)

// notifyReloadSigCh is a no-op on Windows platforms
func notifyReloadSigCh(ch chan os.Signal) {}

func stopNotifyReloadSigCh(ch chan os.Signal) {}

// sendReloadSignal hands the reload to the run. It gives up when ctx ends.
func (p *prog) sendReloadSignal(ctx context.Context) error {
	select {
	case p.reloadCh <- struct{}{}:
		return nil
	case <-time.After(5 * time.Second):
	case <-ctx.Done():
		return ctx.Err()
	}
	return errors.New("timeout while sending reload signal")
}
