package ctrld

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var homedir string

// absHomeDir returns the absolute path to given filename using home directory as root dir.
func absHomeDir(filename string) string {
	if homedir != "" {
		return filepath.Join(homedir, filename)
	}
	dir, err := userHomeDir()
	if err != nil {
		return filename
	}
	return filepath.Join(dir, filename)
}

func dirWritable(dir string) (bool, error) {
	f, err := os.CreateTemp(dir, "")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	return true, f.Close()
}

func userHomeDir() (string, error) {
	// viper will expand for us.
	if runtime.GOOS == "windows" {
		// If we're on windows, use the install path for this.
		exePath, err := os.Executable()
		if err != nil {
			return "", err
		}

		return filepath.Dir(exePath), nil
	}
	dir := "/etc/controld"
	if err := os.MkdirAll(dir, 0750); err != nil {
		return os.UserHomeDir() // fallback to user home directory
	}
	if ok, _ := dirWritable(dir); !ok {
		return os.UserHomeDir()
	}
	return dir, nil
}

// SavedStaticDnsSettingsFilePath returns the file path where the static DNS settings
// for the provided interface are saved.
func SavedStaticDnsSettingsFilePath(iface *net.Interface) string {
	// The file is stored in the user home directory under a hidden file.
	return absHomeDir(".dns_" + iface.Name)
}

// SavedStaticNameservers returns the stored static nameservers for the given interface.
func SavedStaticNameservers(iface *net.Interface) ([]string, string) {
	file := SavedStaticDnsSettingsFilePath(iface)
	data, err := os.ReadFile(file)
	if err != nil || len(data) == 0 {
		return nil, file
	}
	saveValues := strings.Split(string(data), ",")
	var ns []string
	for _, v := range saveValues {
		// Skip any IP that is loopback
		if ip := net.ParseIP(v); ip != nil && ip.IsLoopback() {
			continue
		}
		ns = append(ns, v)
	}
	return ns, file
}
