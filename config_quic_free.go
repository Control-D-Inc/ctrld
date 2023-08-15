//go:build qf

package ctrld

import "net/http"

func (uc *UpstreamConfig) setupDOH3Transport() {}

func (uc *UpstreamConfig) doh3Transport(dnsType uint16) http.RoundTripper { return nil }
