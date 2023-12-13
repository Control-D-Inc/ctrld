package cli

import (
	"errors"
	"os"
	"time"
)

func notifyReloadSigCh(ch chan os.Signal) {}

func (p *prog) sendReloadSignal() error {
	select {
	case p.reloadCh <- struct{}{}:
		return nil
	case <-time.After(5 * time.Second):
	}
	return errors.New("timeout while sending reload signal")
}
