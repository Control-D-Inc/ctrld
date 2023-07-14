package main

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/clientinfo"
	"github.com/Control-D-Inc/ctrld/internal/dnscache"
	"github.com/Control-D-Inc/ctrld/internal/router"
	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
	"github.com/Control-D-Inc/ctrld/internal/router/edgeos"
	"github.com/Control-D-Inc/ctrld/internal/router/firewalla"
)

const (
	defaultSemaphoreCap  = 256
	ctrldLogUnixSock     = "ctrld_start.sock"
	ctrldControlUnixSock = "ctrld_control.sock"
)

var logf = func(format string, args ...any) {
	mainLog.Debug().Msgf(format, args...)
}

var errWindowsAddrInUse = syscall.Errno(0x2740)

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

	cfg     *ctrld.Config
	cache   dnscache.Cacher
	sema    semaphore
	ciTable *clientinfo.Table
	router  router.Router

	started   chan struct{}
	onStarted []func()
	onStopped []func()
}

func (p *prog) Start(s service.Service) error {
	p.cfg = &cfg
	go p.run()
	return nil
}

func (p *prog) run() {
	// Wait the caller to signal that we can do our logic.
	<-p.waitCh
	p.preRun()
	numListeners := len(p.cfg.Listener)
	p.started = make(chan struct{}, numListeners)
	if p.cfg.Service.CacheEnable {
		cacher, err := dnscache.NewLRUCache(p.cfg.Service.CacheSize)
		if err != nil {
			mainLog.Error().Err(err).Msg("failed to create cacher, caching is disabled")
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
				mainLog.Error().Err(err).Str("network", nc.Name).Str("cidr", cidr).Msg("invalid cidr")
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
			mainLog.Info().Msgf("bootstrap IPs for upstream.%s: %q", n, uc.BootstrapIPs())
		} else {
			mainLog.Info().Str("bootstrap_ip", uc.BootstrapIP).Msgf("using bootstrap IP for upstream.%s", n)
		}
		uc.SetCertPool(rootCertPool)
		go uc.Ping()
	}

	p.ciTable = clientinfo.NewTable(&cfg)
	if leaseFile := p.cfg.Service.DHCPLeaseFile; leaseFile != "" {
		mainLog.Debug().Msgf("watching custom lease file: %s", leaseFile)
		format := ctrld.LeaseFileFormat(p.cfg.Service.DHCPLeaseFileFormat)
		p.ciTable.AddLeaseFile(leaseFile, format)
	}
	p.ciTable.Init()
	go p.ciTable.RefreshLoop(p.stopCh)
	go p.watchLinkState()

	for listenerNum := range p.cfg.Listener {
		p.cfg.Listener[listenerNum].Init()
		go func(listenerNum string) {
			defer wg.Done()
			listenerConfig := p.cfg.Listener[listenerNum]
			upstreamConfig := p.cfg.Upstream[listenerNum]
			if upstreamConfig == nil {
				mainLog.Warn().Msgf("no default upstream for: [listener.%s]", listenerNum)
			}
			addr := net.JoinHostPort(listenerConfig.IP, strconv.Itoa(listenerConfig.Port))
			mainLog.Info().Msgf("starting DNS server on listener.%s: %s", listenerNum, addr)
			err := p.serveDNS(listenerNum)
			if err != nil && !defaultConfigWritten && cdUID == "" {
				mainLog.Fatal().Err(err).Msgf("Unable to start dns proxy on listener.%s", listenerNum)
				return
			}
			if err == nil {
				return
			}

			if opErr, ok := err.(*net.OpError); ok && listenerNum == "0" {
				if sErr, ok := opErr.Err.(*os.SyscallError); ok && errors.Is(opErr.Err, syscall.EADDRINUSE) || errors.Is(sErr.Err, errWindowsAddrInUse) {
					mainLog.Warn().Msgf("Address %s already in used, pick a random one", addr)
					ip := randomLocalIP()
					listenerConfig.IP = ip
					port := listenerConfig.Port
					cfg.Upstream = map[string]*ctrld.UpstreamConfig{"0": cfg.Upstream["0"]}
					if err := writeConfigFile(); err != nil {
						mainLog.Fatal().Err(err).Msg("failed to write config file")
					} else {
						mainLog.Info().Msg("writing config file to: " + defaultConfigFile)
					}
					p.mu.Lock()
					p.cfg.Service.AllocateIP = true
					p.mu.Unlock()
					p.preRun()
					mainLog.Info().Msgf("starting DNS server on listener.%s: %s", listenerNum, net.JoinHostPort(ip, strconv.Itoa(port)))
					if err := p.serveDNS(listenerNum); err != nil {
						mainLog.Fatal().Err(err).Msgf("Unable to start dns proxy on listener.%s", listenerNum)
						return
					}
				}
			}
			mainLog.Fatal().Err(err).Msgf("Unable to start dns proxy on listener.%s", listenerNum)
		}(listenerNum)
	}

	for i := 0; i < numListeners; i++ {
		<-p.started
	}
	for _, f := range p.onStarted {
		f()
	}
	// Stop writing log to unix socket.
	consoleWriter.Out = os.Stdout
	initLoggingWithBackup(false)
	if p.logConn != nil {
		_ = p.logConn.Close()
	}
	if p.cs != nil {
		p.registerControlServerHandler()
		if err := p.cs.start(); err != nil {
			mainLog.Warn().Err(err).Msg("could not start control server")
		}
	}
	wg.Wait()
}

func (p *prog) Stop(s service.Service) error {
	close(p.stopCh)
	if err := p.deAllocateIP(); err != nil {
		mainLog.Error().Err(err).Msg("de-allocate ip failed")
		return err
	}
	mainLog.Info().Msg("Service stopped")
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
	logger := mainLog.With().Str("iface", iface).Logger()
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
	if couldBeDirectListener(lc) {
		// If ctrld is direct listener, use 127.0.0.1 as nameserver.
		ns = "127.0.0.1"
	} else if lc.Port != 53 {
		ifaceName := iface
		switch router.Name() {
		case firewalla.Name:
			// On Firewalla, the lo interface is excluded in all dnsmasq settings of all interfaces.
			// Thus, we use "br0" as the nameserver in /etc/resolv.conf file.
			ifaceName = "br0"
			logger.Warn().Msg("using br0 interface IP address as DNS server")
		case edgeos.Name:
			// On EdgeOS, dnsmasq is run with "--local-service", so we need to get
			// the proper interface from dnsmasq config.
			if name, _ := dnsmasq.InterfaceNameFromConfig("/etc/dnsmasq.conf"); name != "" {
				ifaceName = name
				logger.Warn().Msgf("using %s interface IP address as DNS server", ifaceName)
			}
		}
		logger.Warn().Msgf("ctrld is not running on port 53, use interface %s IP as DNS server", ifaceName)
		netIface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			mainLog.Fatal().Err(err).Msg("failed to get default route interface")
		}
		addrs, _ := netIface.Addrs()
		for _, addr := range addrs {
			if netIP, ok := addr.(*net.IPNet); ok && netIP.IP.To4() != nil {
				ns = netIP.IP.To4().String()
				break
			}
		}
	}
	if err := setDNS(netIface, []string{ns}); err != nil {
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
	logger := mainLog.With().Str("iface", iface).Logger()
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
		mainLog.Warn().Err(err).Msg("invalid log sock path")
		return nil
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		mainLog.Warn().Err(err).Msg("could not listen log socket")
		return nil
	}
	defer ln.Close()

	server, err := ln.Accept()
	if err != nil {
		mainLog.Warn().Err(err).Msg("could not accept connection")
		return nil
	}
	return server
}
