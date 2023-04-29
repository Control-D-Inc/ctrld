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
	"github.com/Control-D-Inc/ctrld/internal/dnscache"
	"github.com/Control-D-Inc/ctrld/internal/router"
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

type prog struct {
	mu     sync.Mutex
	waitCh chan struct{}
	stopCh chan struct{}

	cfg   *ctrld.Config
	cache dnscache.Cacher
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
	if p.cfg.Service.CacheEnable {
		cacher, err := dnscache.NewLRUCache(p.cfg.Service.CacheSize)
		if err != nil {
			mainLog.Error().Err(err).Msg("failed to create cacher, caching is disabled")
		} else {
			p.cache = cacher
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
			mainLog.Info().Msgf("Bootstrap IPs for upstream.%s: %q", n, uc.BootstrapIPs())
		} else {
			mainLog.Info().Str("bootstrap_ip", uc.BootstrapIP).Msgf("Using bootstrap IP for upstream.%s", n)
		}
		uc.SetCertPool(rootCertPool)
		uc.SetupTransport()
	}

	go p.watchLinkState()

	for listenerNum := range p.cfg.Listener {
		p.cfg.Listener[listenerNum].Init()
		go func(listenerNum string) {
			defer wg.Done()
			listenerConfig := p.cfg.Listener[listenerNum]
			upstreamConfig := p.cfg.Upstream[listenerNum]
			if upstreamConfig == nil {
				mainLog.Error().Msgf("missing upstream config for: [listener.%s]", listenerNum)
				return
			}
			addr := net.JoinHostPort(listenerConfig.IP, strconv.Itoa(listenerConfig.Port))
			mainLog.Info().Msgf("Starting DNS server on listener.%s: %s", listenerNum, addr)
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
					mainLog.Info().Msgf("Starting DNS server on listener.%s: %s", listenerNum, net.JoinHostPort(ip, strconv.Itoa(port)))
					if err := p.serveDNS(listenerNum); err != nil {
						mainLog.Fatal().Err(err).Msgf("Unable to start dns proxy on listener.%s", listenerNum)
						return
					}
				}
			}
			mainLog.Fatal().Err(err).Msgf("Unable to start dns proxy on listener.%s", listenerNum)
		}(listenerNum)
	}

	wg.Wait()
}

func (p *prog) Stop(s service.Service) error {
	if err := p.deAllocateIP(); err != nil {
		mainLog.Error().Err(err).Msg("de-allocate ip failed")
		return err
	}
	p.preStop()
	if err := router.Stop(); err != nil {
		mainLog.Warn().Err(err).Msg("problem occurred while stopping router")
	}
	mainLog.Info().Msg("Service stopped")
	close(p.stopCh)
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
	switch router.Name() {
	case router.DDWrt, router.OpenWrt, router.Ubios:
		// On router, ctrld run as a DNS forwarder, it does not have to change system DNS.
		// Except for Merlin, which has WAN DNS setup on boot for NTP.
		return
	}
	if cfg.Listener == nil || cfg.Listener["0"] == nil {
		return
	}
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
	if err := setupNetworkManager(); err != nil {
		logger.Error().Err(err).Msg("could not patch NetworkManager")
		return
	}
	logger.Debug().Msg("setting DNS for interface")
	if err := setDNS(netIface, []string{cfg.Listener["0"].IP}); err != nil {
		logger.Error().Err(err).Msgf("could not set DNS for interface")
		return
	}
	logger.Debug().Msg("setting DNS successfully")
}

func (p *prog) resetDNS() {
	switch router.Name() {
	case router.DDWrt, router.OpenWrt, router.Ubios:
		// See comment in p.setDNS method.
		return
	}
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
