package cli

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"syscall"

	"github.com/kardianos/service"
	"tailscale.com/net/interfaces"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/clientinfo"
	"github.com/Control-D-Inc/ctrld/internal/dnscache"
	"github.com/Control-D-Inc/ctrld/internal/router"
)

const (
	defaultSemaphoreCap  = 256
	ctrldLogUnixSock     = "ctrld_start.sock"
	ctrldControlUnixSock = "ctrld_control.sock"
)

var logf = func(format string, args ...any) {
	mainLog.Load().Debug().Msgf(format, args...)
}

var svcConfig = &service.Config{
	Name:        "ctrld",
	DisplayName: "Control-D Helper Service",
	Option:      service.KeyValue{},
}

var useSystemdResolved = false

type prog struct {
	mu      sync.Mutex
	waitCh  chan struct{}
	stopCh  chan struct{}
	logConn net.Conn
	cs      *controlServer

	cfg         *ctrld.Config
	appCallback *AppCallback
	cache       dnscache.Cacher
	sema        semaphore
	ciTable     *clientinfo.Table
	router      router.Router

	started       chan struct{}
	onStartedDone chan struct{}
	onStarted     []func()
	onStopped     []func()
}

func (p *prog) Start(s service.Service) error {
	p.cfg = &cfg
	go p.run()
	return nil
}

func (p *prog) preRun() {
	if !service.Interactive() {
		p.setDNS()
	}
	if runtime.GOOS == "darwin" {
		p.onStopped = append(p.onStopped, func() {
			if !service.Interactive() {
				p.resetDNS()
			}
		})
	}
}

func (p *prog) run() {
	// Wait the caller to signal that we can do our logic.
	<-p.waitCh
	p.preRun()
	numListeners := len(p.cfg.Listener)
	p.started = make(chan struct{}, numListeners)
	p.onStartedDone = make(chan struct{})
	if p.cfg.Service.CacheEnable {
		cacher, err := dnscache.NewLRUCache(p.cfg.Service.CacheSize)
		if err != nil {
			mainLog.Load().Error().Err(err).Msg("failed to create cacher, caching is disabled")
		} else {
			p.cache = cacher
		}
	}
	p.sema = &chanSemaphore{ready: make(chan struct{}, defaultSemaphoreCap)}
	if mcr := p.cfg.Service.MaxConcurrentRequests; mcr != nil {
		n := *mcr
		if n == 0 {
			p.sema = &noopSemaphore{}
		} else {
			p.sema = &chanSemaphore{ready: make(chan struct{}, n)}
		}
	}
	var wg sync.WaitGroup
	wg.Add(len(p.cfg.Listener))

	for _, nc := range p.cfg.Network {
		for _, cidr := range nc.Cidrs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				mainLog.Load().Error().Err(err).Str("network", nc.Name).Str("cidr", cidr).Msg("invalid cidr")
				continue
			}
			nc.IPNets = append(nc.IPNets, ipNet)
		}
	}
	for n := range p.cfg.Upstream {
		uc := p.cfg.Upstream[n]
		uc.Init()
		if uc.BootstrapIP == "" {
			uc.SetupBootstrapIP()
			mainLog.Load().Info().Msgf("bootstrap IPs for upstream.%s: %q", n, uc.BootstrapIPs())
		} else {
			mainLog.Load().Info().Str("bootstrap_ip", uc.BootstrapIP).Msgf("using bootstrap IP for upstream.%s", n)
		}
		uc.SetCertPool(rootCertPool)
		go uc.Ping()
	}

	p.ciTable = clientinfo.NewTable(&cfg, defaultRouteIP(), cdUID)
	if leaseFile := p.cfg.Service.DHCPLeaseFile; leaseFile != "" {
		mainLog.Load().Debug().Msgf("watching custom lease file: %s", leaseFile)
		format := ctrld.LeaseFileFormat(p.cfg.Service.DHCPLeaseFileFormat)
		p.ciTable.AddLeaseFile(leaseFile, format)
	}
	// Newer versions of android and iOS denies permission which breaks connectivity.
	if !isMobile() {
		go func() {
			p.ciTable.Init()
			p.ciTable.RefreshLoop(p.stopCh)
		}()
		go p.watchLinkState()
	}

	for listenerNum := range p.cfg.Listener {
		p.cfg.Listener[listenerNum].Init()
		go func(listenerNum string) {
			defer wg.Done()
			listenerConfig := p.cfg.Listener[listenerNum]
			upstreamConfig := p.cfg.Upstream[listenerNum]
			if upstreamConfig == nil {
				mainLog.Load().Warn().Msgf("no default upstream for: [listener.%s]", listenerNum)
			}
			addr := net.JoinHostPort(listenerConfig.IP, strconv.Itoa(listenerConfig.Port))
			mainLog.Load().Info().Msgf("starting DNS server on listener.%s: %s", listenerNum, addr)
			if err := p.serveDNS(listenerNum); err != nil {
				mainLog.Load().Fatal().Err(err).Msgf("unable to start dns proxy on listener.%s", listenerNum)
			}
		}(listenerNum)
	}

	for i := 0; i < numListeners; i++ {
		<-p.started
	}
	for _, f := range p.onStarted {
		f()
	}
	close(p.onStartedDone)

	// Stop writing log to unix socket.
	consoleWriter.Out = os.Stdout
	initLoggingWithBackup(false)
	if p.logConn != nil {
		_ = p.logConn.Close()
	}
	if p.cs != nil {
		p.registerControlServerHandler()
		if err := p.cs.start(); err != nil {
			mainLog.Load().Warn().Err(err).Msg("could not start control server")
		}
	}
	wg.Wait()
}

func (p *prog) Stop(s service.Service) error {
	mainLog.Load().Info().Msg("Service stopped")
	close(p.stopCh)
	if err := p.deAllocateIP(); err != nil {
		mainLog.Load().Error().Err(err).Msg("de-allocate ip failed")
		return err
	}
	return nil
}

func (p *prog) allocateIP(ip string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.cfg.Service.AllocateIP {
		return nil
	}
	return allocateIP(ip)
}

func (p *prog) deAllocateIP() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.cfg.Service.AllocateIP {
		return nil
	}
	for _, lc := range p.cfg.Listener {
		if err := deAllocateIP(lc.IP); err != nil {
			return err
		}
	}
	return nil
}

func (p *prog) setDNS() {
	if cfg.Listener == nil {
		return
	}
	if iface == "" {
		return
	}
	if iface == "auto" {
		iface = defaultIfaceName()
	}
	lc := cfg.FirstListener()
	if lc == nil {
		return
	}
	logger := mainLog.Load().With().Str("iface", iface).Logger()
	netIface, err := netInterface(iface)
	if err != nil {
		logger.Error().Err(err).Msg("could not get interface")
		return
	}
	if err := setupNetworkManager(); err != nil {
		logger.Error().Err(err).Msg("could not patch NetworkManager")
		return
	}

	logger.Debug().Msg("setting DNS for interface")
	ns := lc.IP
	switch {
	case lc.IsDirectDnsListener():
		// If ctrld is direct listener, use 127.0.0.1 as nameserver.
		ns = "127.0.0.1"
	case lc.Port != 53:
		ns = "127.0.0.1"
		if resolver := router.LocalResolverIP(); resolver != "" {
			ns = resolver
		}
	default:
		// If we ever reach here, it means ctrld is running on lc.IP port 53,
		// so we could just use lc.IP as nameserver.
	}

	nameservers := []string{ns}
	if needRFC1918Listeners(lc) {
		nameservers = append(nameservers, rfc1918Addresses()...)
	}
	if err := setDNS(netIface, nameservers); err != nil {
		logger.Error().Err(err).Msgf("could not set DNS for interface")
		return
	}
	logger.Debug().Msg("setting DNS successfully")
}

func (p *prog) resetDNS() {
	if iface == "" {
		return
	}
	if iface == "auto" {
		iface = defaultIfaceName()
	}
	logger := mainLog.Load().With().Str("iface", iface).Logger()
	netIface, err := netInterface(iface)
	if err != nil {
		logger.Error().Err(err).Msg("could not get interface")
		return
	}
	if err := restoreNetworkManager(); err != nil {
		logger.Error().Err(err).Msg("could not restore NetworkManager")
		return
	}
	logger.Debug().Msg("Restoring DNS for interface")
	if err := resetDNS(netIface); err != nil {
		logger.Error().Err(err).Msgf("could not reset DNS")
		return
	}
	logger.Debug().Msg("Restoring DNS successfully")
}

func randomLocalIP() string {
	n := rand.Intn(254-2) + 2
	return fmt.Sprintf("127.0.0.%d", n)
}

func randomPort() int {
	max := 1<<16 - 1
	min := 1025
	n := rand.Intn(max-min) + min
	return n
}

// runLogServer starts a unix listener, use by startCmd to gather log from runCmd.
func runLogServer(sockPath string) net.Conn {
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("invalid log sock path")
		return nil
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("could not listen log socket")
		return nil
	}
	defer ln.Close()

	server, err := ln.Accept()
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("could not accept connection")
		return nil
	}
	return server
}

func errAddrInUse(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return errors.Is(opErr.Err, syscall.EADDRINUSE) || errors.Is(opErr.Err, windowsEADDRINUSE)
	}
	return false
}

var _ = errAddrInUse

// https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2
var (
	windowsECONNREFUSED = syscall.Errno(10061)
	windowsENETUNREACH  = syscall.Errno(10051)
	windowsEINVAL       = syscall.Errno(10022)
	windowsEADDRINUSE   = syscall.Errno(10048)
)

func errUrlNetworkError(err error) bool {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		var opErr *net.OpError
		if errors.As(urlErr.Err, &opErr) {
			if opErr.Temporary() {
				return true
			}
			switch {
			case errors.Is(opErr.Err, syscall.ECONNREFUSED),
				errors.Is(opErr.Err, syscall.EINVAL),
				errors.Is(opErr.Err, syscall.ENETUNREACH),
				errors.Is(opErr.Err, windowsENETUNREACH),
				errors.Is(opErr.Err, windowsEINVAL),
				errors.Is(opErr.Err, windowsECONNREFUSED):
				return true
			}
		}
	}
	return false
}

func ifaceFirstPrivateIP(iface *net.Interface) string {
	if iface == nil {
		return ""
	}
	do := func(addrs []net.Addr, v4 bool) net.IP {
		for _, addr := range addrs {
			if netIP, ok := addr.(*net.IPNet); ok && netIP.IP.IsPrivate() {
				if v4 {
					return netIP.IP.To4()
				}
				return netIP.IP
			}
		}
		return nil
	}
	addrs, _ := iface.Addrs()
	if ip := do(addrs, true); ip != nil {
		return ip.String()
	}
	if ip := do(addrs, false); ip != nil {
		return ip.String()
	}
	return ""
}

// defaultRouteIP returns private IP string of the default route if present, prefer IPv4 over IPv6.
func defaultRouteIP() string {
	dr, err := interfaces.DefaultRoute()
	if err != nil {
		return ""
	}
	drNetIface, err := netInterface(dr.InterfaceName)
	if err != nil {
		return ""
	}
	mainLog.Load().Debug().Str("iface", drNetIface.Name).Msg("checking default route interface")
	if ip := ifaceFirstPrivateIP(drNetIface); ip != "" {
		mainLog.Load().Debug().Str("ip", ip).Msg("found ip with default route interface")
		return ip
	}

	// If we reach here, it means the default route interface is connected directly to ISP.
	// We need to find the LAN interface with the same Mac address with drNetIface.
	//
	// There could be multiple LAN interfaces with the same Mac address, so we find all private
	// IPs then using the smallest one.
	var addrs []netip.Addr
	interfaces.ForeachInterface(func(i interfaces.Interface, prefixes []netip.Prefix) {
		if i.Name == drNetIface.Name {
			return
		}
		if bytes.Equal(i.HardwareAddr, drNetIface.HardwareAddr) {
			for _, pfx := range prefixes {
				addr := pfx.Addr()
				if addr.IsPrivate() {
					addrs = append(addrs, addr)
				}
			}
		}
	})

	if len(addrs) == 0 {
		mainLog.Load().Warn().Msg("no default route IP found")
		return ""
	}
	sort.Slice(addrs, func(i, j int) bool {
		return addrs[i].Less(addrs[j])
	})

	ip := addrs[0].String()
	mainLog.Load().Debug().Str("ip", ip).Msg("found LAN interface IP")
	return ip
}
