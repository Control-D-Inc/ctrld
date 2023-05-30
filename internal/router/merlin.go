package router

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"unicode"
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
