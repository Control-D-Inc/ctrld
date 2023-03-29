package certs

import (
	"crypto/x509"
	_ "embed"
	"sync"
)

var (
	//go:embed cacert.pem
	caRoots        []byte
	caCertPoolOnce sync.Once
	caCertPool     *x509.CertPool
)

func CACertPool() *x509.CertPool {
	caCertPoolOnce.Do(func() {
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caRoots)
	})
	return caCertPool
}
