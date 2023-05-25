package router

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode"

	"tailscale.com/logtail/backoff"
)

func setupMerlin() error {
	buf, err := os.ReadFile(merlinDNSMasqPostConfPath)
	// Already setup.
	if bytes.Contains(buf, []byte(merlinDNSMasqPostConfMarker)) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	merlinDNSMasqPostConf, err := dnsMasqConf()
	if err != nil {
		return err
	}
	data := strings.Join([]string{
		merlinDNSMasqPostConf,
		"\n",
		merlinDNSMasqPostConfMarker,
		"\n",
		string(buf),
	}, "\n")
	// Write dnsmasq post conf file.
	if err := os.WriteFile(merlinDNSMasqPostConfPath, []byte(data), 0750); err != nil {
		return err
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}

	if err := nvramSetKV(nvramSetupKV(), nvramCtrldSetupKey); err != nil {
		return err
	}

	return nil
}

func cleanupMerlin() error {
	// Restore old configs.
	if err := nvramRestore(nvramSetupKV(), nvramCtrldSetupKey); err != nil {
		return err
	}
	buf, err := os.ReadFile(merlinDNSMasqPostConfPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	// Restore dnsmasq post conf file.
	if err := os.WriteFile(merlinDNSMasqPostConfPath, merlinParsePostConf(buf), 0750); err != nil {
		return err
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func postInstallMerlin() error {
	return nil
}

func merlinRestartDNSMasq() error {
	if out, err := exec.Command("service", "restart_dnsmasq").CombinedOutput(); err != nil {
		return fmt.Errorf("restart_dnsmasq: %s, %w", string(out), err)
	}
	return nil
}

func merlinParsePostConf(buf []byte) []byte {
	if len(buf) == 0 {
		return nil
	}
	parts := bytes.Split(buf, []byte(merlinDNSMasqPostConfMarker))
	if len(parts) != 1 {
		return bytes.TrimLeftFunc(parts[1], unicode.IsSpace)
	}
	return buf
}

func merlinPreStart() (err error) {
	pidFile := "/tmp/ctrld.pid"

	// Remove pid file and trigger dnsmasq restart, so NTP can resolve
	// server name and perform time synchronization.
	pid, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("PreStart: os.Readfile: %w", err)
	}
	if err := os.Remove(pidFile); err != nil {
		return fmt.Errorf("PreStart: os.Remove: %w", err)
	}
	defer func() {
		if werr := os.WriteFile(pidFile, pid, 0600); werr != nil {
			err = errors.Join(err, werr)
			return
		}
		if rerr := restartDNSMasq(); rerr != nil {
			err = errors.Join(err, rerr)
			return
		}
	}()
	if err := restartDNSMasq(); err != nil {
		return fmt.Errorf("PreStart: restartDNSMasqFn: %w", err)
	}

	// Wait until `ntp_ready=1` set.
	b := backoff.NewBackoff("PreStart", func(format string, args ...any) {}, 10*time.Second)
	for {
		out, err := nvram("get", "ntp_ready")
		if err != nil {
			return fmt.Errorf("PreStart: nvram: %w", err)
		}
		if out == "1" {
			return nil
		}
		b.BackOff(context.Background(), errors.New("ntp not ready"))
	}
}
