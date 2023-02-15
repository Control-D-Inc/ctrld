// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || freebsd || openbsd

package dns

import (
	"bytes"
	"fmt"
	"os/exec"
)

// openresolvManager manages DNS configuration using the openresolv
// implementation of the `resolvconf` program.
type openresolvManager struct{}

var _ OSConfigurator = (*openresolvManager)(nil)

func newOpenresolvManager() (openresolvManager, error) {
	return openresolvManager{}, nil
}

func (m openresolvManager) deleteTailscaleConfig() error {
	cmd := exec.Command("resolvconf", "-f", "-d", "ctrld")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("running %s: %s", cmd, out)
	}
	return nil
}

func (m openresolvManager) SetDNS(config OSConfig) error {
	if config.IsZero() {
		return m.deleteTailscaleConfig()
	}

	var stdin bytes.Buffer
	writeResolvConf(&stdin, config.Nameservers, config.SearchDomains)

	cmd := exec.Command("resolvconf", "-m", "0", "-x", "-a", "ctrld")
	cmd.Stdin = &stdin
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("running %s: %s", cmd, out)
	}
	return nil
}

func (m openresolvManager) Close() error {
	return m.deleteTailscaleConfig()
}

func (m openresolvManager) Mode() string {
	return "resolvconf"
}
