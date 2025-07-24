package dnsmasq

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func InterfaceNameFromConfig(filename string) (string, error) {
	buf, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return interfaceNameFromReader(bytes.NewReader(buf))
}

func interfaceNameFromReader(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		after, found := strings.CutPrefix(line, "interface=")
		if found {
			return after, nil
		}
	}
	return "", errors.New("not found")
}

// AdditionalConfigFiles returns a list of Dnsmasq configuration files found in the "/tmp/etc" directory.
func AdditionalConfigFiles() []string {
	if paths, err := filepath.Glob("/tmp/etc/dnsmasq-*.conf"); err == nil {
		return paths
	}
	return nil
}

// AdditionalLeaseFiles returns a list of lease file paths corresponding to the Dnsmasq configuration files.
func AdditionalLeaseFiles() []string {
	cfgFiles := AdditionalConfigFiles()
	if len(cfgFiles) == 0 {
		return nil
	}
	leaseFiles := make([]string, 0, len(cfgFiles))
	for _, cfgFile := range cfgFiles {
		if leaseFile := leaseFileFromConfigFileName(cfgFile); leaseFile != "" {
			leaseFiles = append(leaseFiles, leaseFile)

		} else {
			leaseFiles = append(leaseFiles, defaultLeaseFileFromConfigPath(cfgFile))
		}
	}
	return leaseFiles
}

// leaseFileFromConfigFileName retrieves the DHCP lease file path by reading and parsing the provided configuration file.
func leaseFileFromConfigFileName(cfgFile string) string {
	if f, err := os.Open(cfgFile); err == nil {
		return leaseFileFromReader(f)
	}
	return ""
}

// leaseFileFromReader parses the given io.Reader for the "dhcp-leasefile" configuration and returns its value as a string.
func leaseFileFromReader(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		before, after, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		if before == "dhcp-leasefile" {
			return after
		}
	}
	return ""
}

// defaultLeaseFileFromConfigPath generates the default lease file path based on the provided configuration file path.
func defaultLeaseFileFromConfigPath(path string) string {
	name := filepath.Base(path)
	return filepath.Join("/var/lib/misc", strings.TrimSuffix(name, ".conf")+".leases")
}
