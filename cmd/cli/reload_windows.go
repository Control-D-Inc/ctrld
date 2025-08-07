package cli

import (
	"errors"
	"os"
	"time"
)

// notifyReloadSigCh is a no-op on Windows platforms
func notifyReloadSigCh(ch chan os.Signal) {}

// sendReloadSignal sends a reload signal to the program
func (p *prog) sendReloadSignal() error {
	select {
	case p.reloadCh <- struct{}{}:
		return nil
	case <-time.After(5 * time.Second):
	}
	return errors.New("timeout while sending reload signal")
}
