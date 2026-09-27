package nvram

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const (
	CtrldKeyPrefix  = "ctrld_"
	CtrldSetupKey   = "ctrld_setup"
	CtrldInstallKey = "ctrld_install"
	RCStartupKey    = "rc_startup"
)

// Run runs the given nvram command.
func Run(args ...string) (string, error) {
	cmd := exec.Command("nvram", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s:%w", stderr.String(), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

/*
NOTE:
  - For Openwrt, DNSSEC is not included in default dnsmasq (require dnsmasq-full).
  - For Merlin, DNSSEC is configured during postconf script (see merlinDNSMasqPostConfTmpl).
  - For Ubios UDM Pro/Dream Machine, DNSSEC is not included in their dnsmasq package:
    +https://community.ui.com/questions/Implement-DNSSEC-into-UniFi/951c72b0-4d88-4c86-9174-45417bd2f9ca
    +https://community.ui.com/questions/Enable-DNSSEC-for-Unifi-Dream-Machine-FW-updates/e68e367c-d09b-4459-9444-18908f7c1ea1
*/

// SetKV writes the given key/value from map to nvram.
// The given setupKey is set to 1 to indicate key/value set.
//
// Keep the long-standing generic semantics for router backends which do not
// have Merlin's retrying PreRun reconciliation.
func SetKV(m map[string]string, setupKey string) error {
	for key, value := range m {
		old, err := Run("get", key)
		if err != nil {
			return fmt.Errorf("%s: %w", old, err)
		}
		if out, err := Run("set", CtrldKeyPrefix+key+"="+old); err != nil {
			return fmt.Errorf("%s: %w", out, err)
		}
		if out, err := Run("set", key+"="+value); err != nil {
			return fmt.Errorf("%s: %w", out, err)
		}
	}
	if out, err := Run("set", setupKey+"=1"); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	if out, err := Run("commit"); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	return nil
}

// SetKVWithVolatileRetryMarker is Merlin's transactional SetKV variant.
// It rolls back partially-applied values on failure. If that rollback cannot
// be made durable, setupKey is re-armed only in volatile NVRAM so Merlin's
// deferred/retrying Cleanup can reconcile the same boot without persisting a
// false "setup completed" marker for the next boot.
func SetKVWithVolatileRetryMarker(m map[string]string, setupKey string) error {
	modified := make([]string, 0, len(m))

	rearmVolatile := func(cause error) error {
		if out, err := Run("set", setupKey+"=1"); err != nil {
			return errors.Join(
				cause,
				fmt.Errorf("failed to re-arm volatile %s: %s: %w", setupKey, out, err),
			)
		}
		return cause
	}

	rollback := func(cause error) error {
		var restoreErr error
		for i := len(modified) - 1; i >= 0; i-- {
			key := modified[i]
			ctrldKey := CtrldKeyPrefix + key
			old, err := Run("get", ctrldKey)
			if err != nil {
				restoreErr = errors.Join(restoreErr, fmt.Errorf("read rollback %s: %w", ctrldKey, err))
				continue
			}
			if out, err := Run("set", key+"="+old); err != nil {
				restoreErr = errors.Join(restoreErr, fmt.Errorf("%s: %w", out, err))
			}
		}
		if restoreErr != nil {
			return rearmVolatile(errors.Join(
				cause,
				fmt.Errorf("nvram rollback incomplete: %w", restoreErr),
			))
		}

		if out, err := Run("unset", setupKey); err != nil {
			return rearmVolatile(errors.Join(cause, fmt.Errorf("%s: %w", out, err)))
		}
		if out, err := Run("commit"); err != nil {
			return rearmVolatile(errors.Join(
				cause,
				fmt.Errorf("nvram rollback commit failed: %s: %w", out, err),
			))
		}
		return cause
	}

	fail := func(err error) error {
		if len(modified) == 0 {
			return err
		}
		return rollback(err)
	}

	for key, value := range m {
		old, err := Run("get", key)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", old, err))
		}
		if out, err := Run("set", CtrldKeyPrefix+key+"="+old); err != nil {
			return fail(fmt.Errorf("%s: %w", out, err))
		}
		modified = append(modified, key)
		if out, err := Run("set", key+"="+value); err != nil {
			return rollback(fmt.Errorf("%s: %w", out, err))
		}
	}

	if out, err := Run("set", setupKey+"=1"); err != nil {
		return rollback(fmt.Errorf("%s: %w", out, err))
	}
	if out, err := Run("commit"); err != nil {
		return rollback(fmt.Errorf("%s: %w", out, err))
	}
	return nil
}

// Restore restores the old value of each key from ctrld's backup NVRAM.
// Backup keys are deliberately retained after the restore commit. They are tiny,
// harmless, and keeping them avoids a second non-transactional "cleanup commit"
// that could destroy the only rollback copy after a transient nvram failure.
// A future SetKV overwrites each backup with the then-current value.
func Restore(m map[string]string, setupKey string) error {
	return restore(m, setupKey, false)
}

// RestoreWithVolatileRetryMarker is Merlin's retry-aware Restore variant.
// If the persistent restore commit fails after setupKey was unset in the
// volatile NVRAM view, setupKey is re-armed only in RAM so Merlin PreRun can
// retry Cleanup in the same boot. Other router backends intentionally use
// Restore and keep their existing one-shot semantics.
func RestoreWithVolatileRetryMarker(m map[string]string, setupKey string) error {
	return restore(m, setupKey, true)
}

func restore(m map[string]string, setupKey string, rearmVolatile bool) error {
	for key := range m {
		ctrldKey := CtrldKeyPrefix + key
		old, err := Run("get", ctrldKey)
		if err != nil {
			return fmt.Errorf("%s: %w", old, err)
		}
		if out, err := Run("set", key+"="+old); err != nil {
			return fmt.Errorf("%s: %w", out, err)
		}
	}

	if out, err := Run("unset", setupKey); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	if out, err := Run("commit"); err != nil {
		commitErr := fmt.Errorf("%s: %w", out, err)
		if !rearmVolatile {
			return commitErr
		}

		// Merlin retries Cleanup during PreRun. The persistent commit may have
		// failed while the volatile NVRAM view already has setupKey unset.
		// Re-arm setupKey only in RAM so that same-boot retry remains possible,
		// but do not commit it: if the restored values actually reached flash
		// despite the reported error, reboot must not resurrect a completed setup.
		if markerOut, markerErr := Run("set", setupKey+"=1"); markerErr != nil {
			return errors.Join(
				commitErr,
				fmt.Errorf("failed to re-arm volatile %s after restore commit failure: %s: %w", setupKey, markerOut, markerErr),
			)
		}
		return commitErr
	}
	return nil
}
