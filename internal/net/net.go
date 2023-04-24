package net

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/logtail/backoff"
)

const (
	controldIPv6Test = "ipv6.controld.io"
	controldIPv4Test = "ipv4.controld.io"
	bootstrapDNS     = "76.76.2.0:53"
)

var Dialer = &net.Dialer{
	Resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 10 * time.Second,
			}
			return d.DialContext(ctx, "udp", bootstrapDNS)
		},
	},
}

const probeStackTimeout = 2 * time.Second

var probeStackDialer = &net.Dialer{
	Resolver: Dialer.Resolver,
	Timeout:  probeStackTimeout,
}

var (
	stackOnce          atomic.Pointer[sync.Once]
	ipv6Enabled        bool
	canListenIPv6Local bool
	hasNetworkUp       bool
)

func init() {
	stackOnce.Store(new(sync.Once))
}

func supportIPv4() bool {
	_, err := probeStackDialer.Dial("tcp4", net.JoinHostPort(controldIPv4Test, "80"))
	return err == nil
}

func supportIPv6(ctx context.Context) bool {
	_, err := probeStackDialer.DialContext(ctx, "tcp6", net.JoinHostPort(controldIPv6Test, "80"))
	return err == nil
}

func supportListenIPv6Local() bool {
	if ln, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		ln.Close()
		return true
	}
	return false
}

func probeStack() {
	b := backoff.NewBackoff("probeStack", func(format string, args ...any) {}, 5*time.Second)
	for {
		if _, err := probeStackDialer.Dial("udp", bootstrapDNS); err == nil {
			hasNetworkUp = true
			break
		} else {
			b.BackOff(context.Background(), err)
		}
	}
	ipv6Enabled = supportIPv6(context.Background())
	canListenIPv6Local = supportListenIPv6Local()
}

func Up() bool {
	stackOnce.Load().Do(probeStack)
	return hasNetworkUp
}

func SupportsIPv6() bool {
	stackOnce.Load().Do(probeStack)
	return ipv6Enabled
}

func SupportsIPv6ListenLocal() bool {
	stackOnce.Load().Do(probeStack)
	return canListenIPv6Local
}

// IPv6Available is like SupportsIPv6, but always do the check without caching.
func IPv6Available(ctx context.Context) bool {
	return supportIPv6(ctx)
}

// IsIPv6 checks if the provided IP is v6.
//
//lint:ignore U1000 use in os_windows.go
func IsIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() == nil && parsedIP.To16() != nil
}

type parallelDialerResult struct {
	conn net.Conn
	err  error
}

type ParallelDialer struct {
	net.Dialer
}

func (d *ParallelDialer) DialContext(ctx context.Context, network string, addrs []string) (net.Conn, error) {
	if len(addrs) == 0 {
		return nil, errors.New("empty addresses")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan *parallelDialerResult, len(addrs))
	var wg sync.WaitGroup
	wg.Add(len(addrs))
	go func() {
		wg.Wait()
		close(ch)
	}()

	for _, addr := range addrs {
		go func(addr string) {
			defer wg.Done()
			conn, err := d.Dialer.DialContext(ctx, network, addr)
			ch <- &parallelDialerResult{conn: conn, err: err}
		}(addr)
	}

	errs := make([]error, 0, len(addrs))
	for res := range ch {
		if res.err == nil {
			cancel()
			return res.conn, res.err
		}
		errs = append(errs, res.err)
	}

	return nil, errors.Join(errs...)
}
