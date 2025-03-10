package net

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"tailscale.com/logtail/backoff"
)

const (
	v4BootstrapDNS = "76.76.2.22:53"
	v6BootstrapDNS = "[2606:1a40::22]:53"
)

var Dialer = &net.Dialer{
	Resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := ParallelDialer{}
			d.Timeout = 10 * time.Second
			l := zerolog.New(io.Discard)
			return d.DialContext(ctx, "udp", []string{v4BootstrapDNS, v6BootstrapDNS}, &l)
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
	c, err := probeStackDialer.DialContext(ctx, "tcp6", v6BootstrapDNS)
	if err != nil {
		return false
	}
	c.Close()
	return true
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

// IsLinkLocalUnicastIPv6 checks if the provided IP is a link local unicast v6 address.
func IsLinkLocalUnicastIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || parsedIP.To4() != nil || parsedIP.To16() == nil {
		return false
	}
	return parsedIP.To16().IsLinkLocalUnicast()
}

type parallelDialerResult struct {
	conn net.Conn
	err  error
}

type ParallelDialer struct {
	net.Dialer
}

func (d *ParallelDialer) DialContext(ctx context.Context, network string, addrs []string, logger *zerolog.Logger) (net.Conn, error) {
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
			logger.Debug().Msgf("dialing to %s", addr)
			conn, err := d.Dialer.DialContext(ctx, network, addr)
			if err != nil {
				logger.Debug().Msgf("failed to dial %s: %v", addr, err)
			}
			select {
			case ch <- &parallelDialerResult{conn: conn, err: err}:
			case <-done:
				if conn != nil {
					logger.Debug().Msgf("connection closed: %s", conn.RemoteAddr())
					conn.Close()
				}
			}
		}(addr)
	}

	errs := make([]error, 0, len(addrs))
	for res := range ch {
		if res.err == nil {
			cancel()
			logger.Debug().Msgf("connected to %s", res.conn.RemoteAddr())
			return res.conn, res.err
		}
		errs = append(errs, res.err)
	}
	return nil, errors.Join(errs...)
}
