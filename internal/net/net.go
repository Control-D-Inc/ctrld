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

	"go.uber.org/zap"
	"tailscale.com/logtail/backoff"
)

const (
	v4BootstrapDNS    = "76.76.2.22:53"
	v6BootstrapDNS    = "[2606:1a40::22]:53"
	v6BootstrapIP     = "2606:1a40::22"
	defaultHTTPSPort  = "443"
	defaultHTTPPort   = "80"
	defaultDNSPort    = "53"
	probeStackTimeout = 2 * time.Second
)

var commonIPv6Ports = []string{defaultHTTPSPort, defaultHTTPPort, defaultDNSPort}

var Dialer = &net.Dialer{
	Resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := ParallelDialer{}
			d.Timeout = 10 * time.Second
			l := zap.NewNop()
			return d.DialContext(ctx, "udp", []string{v4BootstrapDNS, v6BootstrapDNS}, l)
		},
	},
}

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

// supportIPv6 checks for IPv6 connectivity by attempting to connect to predefined ports
// on a specific IPv6 address.
// Returns a boolean indicating if IPv6 is supported and the port on which the connection succeeded.
// If no connection is successful, returns false and an empty string.
func supportIPv6(ctx context.Context) (supported bool, successPort string) {
	for _, port := range commonIPv6Ports {
		if canConnectToIPv6Port(ctx, port) {
			return true, string(port)
		}
	}
	return false, ""
}

// canConnectToIPv6Port attempts to establish a TCP connection to the specified port
// using IPv6. Returns true if the connection was successful.
func canConnectToIPv6Port(ctx context.Context, port string) bool {
	address := net.JoinHostPort(v6BootstrapIP, port)
	conn, err := probeStackDialer.DialContext(ctx, "tcp6", address)
	if err != nil {
		return false
	}
	_ = conn.Close()
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
	hasV6, _ := supportIPv6(ctx)
	return hasV6
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

const (
	// unreachableBackoffBase is the initial suppression window applied to a
	// dial address after it returns a network-unreachable error (e.g.
	// "connect: no route to host"). The window grows exponentially up to
	// unreachableBackoffMax on repeated failures, and is cleared as soon as
	// the address dials successfully.
	unreachableBackoffBase = 5 * time.Second
	// unreachableBackoffMax caps the suppression window so an address is
	// always re-probed within a bounded interval, preserving recovery when
	// the route comes back.
	unreachableBackoffMax = 60 * time.Second
)

// Windows winsock codes for the unreachable errnos. A failing connect on
// Windows surfaces these raw WSA codes (WSAENETUNREACH/WSAEHOSTUNREACH), whereas
// syscall.ENETUNREACH/EHOSTUNREACH are Go's portable "invented" values
// (APPLICATION_ERROR + iota) that never equal them. Matching these explicitly is
// therefore required for the classifier to detect unreachable errors on Windows;
// errors.Is against the syscall.* constants alone would not.
//
// https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2
var (
	windowsENETUNREACH  = syscall.Errno(10051)
	windowsEHOSTUNREACH = syscall.Errno(10065)
)

// IsUnreachable reports whether err indicates the destination network or host
// has no route (ENETUNREACH/EHOSTUNREACH). These are the errors produced when
// an endpoint's address family is available locally but unroutable, e.g. an
// IPv6 DoH endpoint while the host has IPv6 but no route to it.
func IsUnreachable(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return errors.Is(opErr.Err, syscall.ENETUNREACH) ||
			errors.Is(opErr.Err, syscall.EHOSTUNREACH) ||
			errors.Is(opErr.Err, windowsENETUNREACH) ||
			errors.Is(opErr.Err, windowsEHOSTUNREACH)
	}
	return false
}

type unreachableEntry struct {
	until   time.Time
	backoff time.Duration
}

// unreachableTracker records dial addresses that recently failed with a
// network-unreachable error so ParallelDialer can temporarily stop hammering
// them. This prevents an unroutable endpoint from generating a sustained dial
// /health-check storm, while still re-probing each address once its bounded
// backoff window expires so genuine recovery is never permanently blocked.
type unreachableTracker struct {
	mu      sync.Mutex
	entries map[string]unreachableEntry
}

var unreachable = &unreachableTracker{entries: make(map[string]unreachableEntry)}

// suppressed reports whether addr is currently within its unreachable backoff
// window and should be skipped.
func (t *unreachableTracker) suppressed(addr string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[addr]
	return ok && now.Before(e.until)
}

// markUnreachable extends the suppression window for addr using a bounded
// exponential backoff.
func (t *unreachableTracker) markUnreachable(addr string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[addr]
	if e.backoff == 0 {
		e.backoff = unreachableBackoffBase
	} else {
		e.backoff *= 2
		if e.backoff > unreachableBackoffMax {
			e.backoff = unreachableBackoffMax
		}
	}
	e.until = now.Add(e.backoff)
	t.entries[addr] = e
}

// markReachable clears any suppression for addr after a successful dial.
func (t *unreachableTracker) markReachable(addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, addr)
}

type ParallelDialer struct {
	net.Dialer
}

func (d *ParallelDialer) DialContext(ctx context.Context, network string, addrs []string, logger *zap.Logger) (net.Conn, error) {
	if len(addrs) == 0 {
		return nil, errors.New("empty addresses")
	}

	// Skip addresses that recently returned a network-unreachable error so an
	// unroutable endpoint (e.g. an IPv6 DoH address while the host has IPv6
	// but no route to it) does not generate a sustained dial storm. Suppression
	// is bounded: once an address's backoff window expires it is re-probed, so
	// genuine recovery is preserved.
	now := time.Now()
	live := make([]string, 0, len(addrs))
	var suppressed int
	for _, addr := range addrs {
		if unreachable.suppressed(addr, now) {
			suppressed++
			continue
		}
		live = append(live, addr)
	}
	if len(live) == 0 {
		// Every candidate is within its unreachable backoff window. Fail fast
		// and quietly instead of re-dialing known-unroutable addresses; the
		// windows expire and re-probe shortly, so recovery still happens.
		logger.Debug("Skipping unreachable addresses, all in backoff", zap.Int("suppressed", suppressed))
		// TODO: the errno here is hardcoded to EHOSTUNREACH, but the actual
		// failure that triggered suppression may have been ENETUNREACH. This is
		// harmless today (IsUnreachable treats both the same and nothing else
		// inspects the errno), but if these errors are ever recorded/reported we
		// should retain the real error in unreachableEntry and surface it here.
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.EHOSTUNREACH}
	}
	if suppressed > 0 {
		logger.Debug("Skipping unreachable addresses in backoff", zap.Int("suppressed", suppressed))
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan struct{})
	defer close(done)
	ch := make(chan *parallelDialerResult, len(live))
	var wg sync.WaitGroup
	wg.Add(len(live))
	go func() {
		wg.Wait()
		close(ch)
	}()

	for _, addr := range live {
		go func(addr string) {
			defer wg.Done()
			logger.Debug("Dialing to", zap.String("address", addr))
			conn, err := d.Dialer.DialContext(ctx, network, addr)
			if err != nil {
				logger.Debug("Failed to dial", zap.String("address", addr), zap.Error(err))
				if IsUnreachable(err) {
					unreachable.markUnreachable(addr, time.Now())
				}
			} else {
				unreachable.markReachable(addr)
			}
			select {
			case ch <- &parallelDialerResult{conn: conn, err: err}:
			case <-done:
				if conn != nil {
					logger.Debug("Connection closed", zap.String("remote_address", conn.RemoteAddr().String()))
					conn.Close()
				}
			}
		}(addr)
	}

	errs := make([]error, 0, len(addrs))
	for res := range ch {
		if res.err == nil {
			cancel()
			logger.Debug("Connected to", zap.String("remote_address", res.conn.RemoteAddr().String()))
			return res.conn, res.err
		}
		errs = append(errs, res.err)
	}
	return nil, errors.Join(errs...)
}
