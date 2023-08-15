package ntp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"tailscale.com/logtail/backoff"

	"github.com/Control-D-Inc/ctrld/internal/router/nvram"
)

// WaitNvram waits NTP synced by checking "ntp_ready" value using nvram.
func WaitNvram() error {
	// Wait until `ntp_ready=1` set.
	b := backoff.NewBackoff("ntp.Wait", func(format string, args ...any) {}, 10*time.Second)
	for {
		// ddwrt use "ntp_done": https://github.com/mirror/dd-wrt/blob/a08c693527ab3204bf7bebd408a7c9a83b6ede47/src/router/rc/ntp.c#L100
		for _, key := range []string{"ntp_ready", "ntp_done"} {
			out, err := nvram.Run("get", key)
			if err != nil {
				return fmt.Errorf("PreStart: nvram: %w", err)
			}
			if out == "1" {
				return nil
			}
		}
		b.BackOff(context.Background(), errors.New("ntp not ready"))
	}
}

// WaitUpstart waits NTP synced by checking upstart task "ntpsync" is in "stop/waiting" state.
func WaitUpstart() error {
	// Wait until `initctl status ntpsync` returns stop state.
	b := backoff.NewBackoff("ntp.WaitUpstart", func(format string, args ...any) {}, 10*time.Second)
	for {
		out, err := exec.Command("initctl", "status", "ntpsync").CombinedOutput()
		if err != nil {
			return fmt.Errorf("exec.Command: %w", err)
		}
		if bytes.Contains(out, []byte("stop/waiting")) {
			return nil
		}
		b.BackOff(context.Background(), errors.New("ntp not ready"))
	}
}
