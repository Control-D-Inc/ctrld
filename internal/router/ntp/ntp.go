package ntp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Control-D-Inc/ctrld/internal/router/nvram"
	"tailscale.com/logtail/backoff"
)

func Wait() error {
	// Wait until `ntp_ready=1` set.
	b := backoff.NewBackoff("ntp.Wait", func(format string, args ...any) {}, 10*time.Second)
	for {
		out, err := nvram.Run("get", "ntp_ready")
		if err != nil {
			return fmt.Errorf("PreStart: nvram: %w", err)
		}
		if out == "1" {
			return nil
		}
		b.BackOff(context.Background(), errors.New("ntp not ready"))
	}
}
