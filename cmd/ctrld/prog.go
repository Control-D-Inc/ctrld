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
	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/dnscache"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

var logf = func(format string, args ...any) {
	mainLog.Debug().Msgf(format, args...)
}

var errWindowsAddrInUse = syscall.Errno(0x2740)

var svcConfig = &service.Config{
	Name:        "ctrld",
	DisplayName: "Control-D Helper Service",
}

type prog struct {
	cfg   *ctrld.Config
	cache dnscache.Cacher
}

func (p *prog) Start(s service.Service) error {
	p.cfg = &cfg
	go p.run()
	mainLog.Info().Msg("Service started")
	return nil
}

func (p *prog) run() {
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
			// resolve it manually and set the bootstrap ip
			c := new(dns.Client)
			for _, dnsType := range []uint16{dns.TypeAAAA, dns.TypeA} {
				if !ctrldnet.SupportsIPv6() && dnsType == dns.TypeAAAA {
					continue
				}
				m := new(dns.Msg)
				m.SetQuestion(uc.Domain+".", dnsType)
				m.RecursionDesired = true
				r, _, err := c.Exchange(m, net.JoinHostPort(bootstrapDNS, "53"))
				if err != nil {
					mainLog.Error().Err(err).Msgf("could not resolve domain %s for upstream.%s", uc.Domain, n)
					continue
				}
				if r.Rcode != dns.RcodeSuccess {
					mainLog.Error().Msgf("could not resolve domain return code: %d, upstream.%s", r.Rcode, n)
					continue
				}
				if len(r.Answer) == 0 {
					continue
				}
				for _, a := range r.Answer {
					switch ar := a.(type) {
					case *dns.A:
						uc.BootstrapIP = ar.A.String()
					case *dns.AAAA:
						uc.BootstrapIP = ar.AAAA.String()
					default:
						continue
					}
					mainLog.Info().Str("bootstrap_ip", uc.BootstrapIP).Msgf("Setting bootstrap IP for upstream.%s", n)
					// Stop if we reached here, because we got the bootstrap IP from r.Answer.
					break
				}
				// If we reached here, uc.BootstrapIP was set, nothing to do anymore.
				break
			}
		}
		uc.SetupTransport()
	}

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
			err := p.serveUDP(listenerNum)
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
					p.cfg.Service.AllocateIP = true
					p.preRun()
					mainLog.Info().Msgf("Starting DNS server on listener.%s: %s", listenerNum, net.JoinHostPort(ip, strconv.Itoa(port)))
					if err := p.serveUDP(listenerNum); err != nil {
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
	mainLog.Info().Msg("Service stopped")
	return nil
}

func (p *prog) allocateIP(ip string) error {
	if !p.cfg.Service.AllocateIP {
		return nil
	}
	return allocateIP(ip)
}

func (p *prog) deAllocateIP() error {
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
