package dnsmasq

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
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
