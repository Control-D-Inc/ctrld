package net

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"tailscale.com/logtail/backoff"
)

const (
	controldIPv6Test = "ipv6.controld.io"
	v4BootstrapDNS   = "76.76.2.0:53"
	v6BootstrapDNS   = "[2606:1a40::]:53"
)

var Dialer = &net.Dialer{
	Resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := ParallelDialer{}
			d.Timeout = 10 * time.Second
			return d.DialContext(ctx, "udp", []string{v4BootstrapDNS, v6BootstrapDNS})
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
	canListenIPv6Local bool
	hasNetworkUp       bool
)

func init() {
	stackOnce.Store(new(sync.Once))
}

func supportIPv6(ctx context.Context) bool {
	_, err := probeStackDialer.DialContext(ctx, "tcp6", net.JoinHostPort(controldIPv6Test, "443"))
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		<-sigs
		cancel()
	}()

	b := backoff.NewBackoff("probeStack", func(format string, args ...any) {}, 5*time.Second)
	for {
		if _, err := probeStackDialer.DialContext(ctx, "udp", v4BootstrapDNS); err == nil {
			hasNetworkUp = true
			break
		}
		if _, err := probeStackDialer.DialContext(ctx, "udp", v6BootstrapDNS); err == nil {
			hasNetworkUp = true
			break
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		b.BackOff(context.Background(), errors.New("network is down"))
	}
	canListenIPv6Local = supportListenIPv6Local()
}

func Up() bool {
	stackOnce.Load().Do(probeStack)
	return hasNetworkUp
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

	done := make(chan struct{})
	defer close(done)
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
			select {
			case ch <- &parallelDialerResult{conn: conn, err: err}:
			case <-done:
				if conn != nil {
					conn.Close()
				}
			}
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
