package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"golang.org/x/sync/singleflight"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/clientinfo"
	"github.com/Control-D-Inc/ctrld/internal/controld"
	"github.com/Control-D-Inc/ctrld/internal/dnscache"
	"github.com/Control-D-Inc/ctrld/internal/router"
)

const (
	defaultSemaphoreCap  = 256
	ctrldLogUnixSock     = "ctrld_start.sock"
	ctrldControlUnixSock = "ctrld_control.sock"
	// iOS unix socket name max length is 11.
	ctrldControlUnixSockMobile = "cd.sock"
	upstreamPrefix             = "upstream."
	upstreamOS                 = upstreamPrefix + "os"
	upstreamPrivate            = upstreamPrefix + "private"
	dnsWatchdogDefaultInterval = 20 * time.Second
)

// ControlSocketName returns name for control unix socket.
func ControlSocketName() string {
	if isMobile() {
		return ctrldControlUnixSockMobile
	} else {
		return ctrldControlUnixSock
	}
}

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
	mu                   sync.Mutex
	waitCh               chan struct{}
	stopCh               chan struct{}
	reloadCh             chan struct{} // For Windows.
	reloadDoneCh         chan struct{}
	apiReloadCh          chan *ctrld.Config
	apiForceReloadCh     chan struct{}
	apiForceReloadGroup  singleflight.Group
	logConn              net.Conn
	cs                   *controlServer
	csSetDnsDone         chan struct{}
	csSetDnsOk           bool
	dnsWg                sync.WaitGroup
	dnsWatcherClosedOnce sync.Once
	dnsWatcherStopCh     chan struct{}
	rc                   *controld.ResolverConfig

	cfg                       *ctrld.Config
	localUpstreams            []string
	ptrNameservers            []string
	appCallback               *AppCallback
	cache                     dnscache.Cacher
	cacheFlushDomainsMap      map[string]struct{}
	sema                      semaphore
	ciTable                   *clientinfo.Table
	um                        *upstreamMonitor
	router                    router.Router
	ptrLoopGuard              *loopGuard
	lanLoopGuard              *loopGuard
	metricsQueryStats         atomic.Bool
	queryFromSelfMap          sync.Map
	initInternalLogWriterOnce sync.Once
	internalLogWriter         *logWriter
	internalLogSent           time.Time
	runningIface              string
	requiredMultiNICsConfig   bool

	selfUninstallMu       sync.Mutex
	refusedQueryCount     int
	canSelfUninstall      atomic.Bool
	checkingSelfUninstall bool

	loopMu sync.Mutex
	loop   map[string]bool

	leakingQueryMu     sync.Mutex
	leakingQueryWasRun bool
	leakingQuery       atomic.Bool

	started       chan struct{}
	onStartedDone chan struct{}
	onStarted     []func()
	onStopped     []func()
}

func (p *prog) Start(s service.Service) error {
	go p.runWait()
	return nil
}

// runWait runs ctrld components, waiting for signal to reload.
func (p *prog) runWait() {
	p.mu.Lock()
	p.cfg = &cfg
	p.mu.Unlock()
	reloadSigCh := make(chan os.Signal, 1)
	notifyReloadSigCh(reloadSigCh)

	reload := false
	logger := mainLog.Load()
	for {
		reloadCh := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			p.run(reload, reloadCh)
			reload = true
		}()

		var newCfg *ctrld.Config
		select {
		case sig := <-reloadSigCh:
			logger.Notice().Msgf("got signal: %s, reloading...", sig.String())
		case <-p.reloadCh:
			logger.Notice().Msg("reloading...")
		case apiCfg := <-p.apiReloadCh:
			newCfg = apiCfg
		case <-p.stopCh:
			close(reloadCh)
			return
		}

		waitOldRunDone := func() {
			close(reloadCh)
			<-done
		}

		if newCfg == nil {
			newCfg = &ctrld.Config{}
			confFile := v.ConfigFileUsed()
			v := viper.NewWithOptions(viper.KeyDelimiter("::"))
			ctrld.InitConfig(v, "ctrld")
			if configPath != "" {
				confFile = configPath
			}
			v.SetConfigFile(confFile)
			if err := v.ReadInConfig(); err != nil {
				logger.Err(err).Msg("could not read new config")
				waitOldRunDone()
				continue
			}
			if err := v.Unmarshal(&newCfg); err != nil {
				logger.Err(err).Msg("could not unmarshal new config")
				waitOldRunDone()
				continue
			}
			if cdUID != "" {
				if rc, err := processCDFlags(newCfg); err != nil {
					logger.Err(err).Msg("could not fetch ControlD config")
					waitOldRunDone()
					continue
				} else {
					p.mu.Lock()
					p.rc = rc
					p.mu.Unlock()
				}
			}
		}

		waitOldRunDone()

		p.mu.Lock()
		curListener := p.cfg.Listener
		p.mu.Unlock()

		for n, lc := range newCfg.Listener {
			curLc := curListener[n]
			if curLc == nil {
				continue
			}
			if lc.IP == "" {
				lc.IP = curLc.IP
			}
			if lc.Port == 0 {
				lc.Port = curLc.Port
			}
		}
		if err := validateConfig(newCfg); err != nil {
			logger.Err(err).Msg("invalid config")
			continue
		}

		addExtraSplitDnsRule(newCfg)
		if err := writeConfigFile(newCfg); err != nil {
			logger.Err(err).Msg("could not write new config")
		}

		// This needs to be done here, otherwise, the DNS handler may observe an invalid
		// upstream config because its initialization function have not been called yet.
		mainLog.Load().Debug().Msg("setup upstream with new config")
		p.setupUpstream(newCfg)

		p.mu.Lock()
		*p.cfg = *newCfg
		p.mu.Unlock()

		logger.Notice().Msg("reloading config successfully")

		select {
		case p.reloadDoneCh <- struct{}{}:
		default:
		}
	}
}

func (p *prog) preRun() {
	if iface == "auto" {
		iface = defaultIfaceName()
		p.requiredMultiNICsConfig = requiredMultiNICsConfig()
	}
	p.runningIface = iface
	if runtime.GOOS == "darwin" {
		p.onStopped = append(p.onStopped, func() {
			if !service.Interactive() {
				p.resetDNS()
			}
		})
	}
}

func (p *prog) postRun() {
	if !service.Interactive() {
		p.resetDNS()
		ns := ctrld.InitializeOsResolver()
		mainLog.Load().Debug().Msgf("initialized OS resolver with nameservers: %v", ns)
		p.setDNS()
		p.csSetDnsDone <- struct{}{}
		close(p.csSetDnsDone)
	}
}

// apiConfigReload calls API to check for latest config update then reload ctrld if necessary.
func (p *prog) apiConfigReload() {
	if cdUID == "" {
		return
	}

	ticker := time.NewTicker(timeDurationOrDefault(p.cfg.Service.RefetchTime, 3600) * time.Second)
	defer ticker.Stop()

	logger := mainLog.Load().With().Str("mode", "api-reload").Logger()
	logger.Debug().Msg("starting custom config reload timer")
	lastUpdated := time.Now().Unix()

	doReloadApiConfig := func(forced bool, logger zerolog.Logger) {
		resolverConfig, err := controld.FetchResolverConfig(cdUID, rootCmd.Version, cdDev)
		selfUninstallCheck(err, p, logger)
		if err != nil {
			logger.Warn().Err(err).Msg("could not fetch resolver config")
			return
		}

		if resolverConfig.DeactivationPin != nil {
			newDeactivationPin := *resolverConfig.DeactivationPin
			curDeactivationPin := cdDeactivationPin.Load()
			switch {
			case curDeactivationPin != defaultDeactivationPin:
				logger.Debug().Msg("saving deactivation pin")
			case curDeactivationPin != newDeactivationPin:
				logger.Debug().Msg("update deactivation pin")
			}
			cdDeactivationPin.Store(newDeactivationPin)
		} else {
			cdDeactivationPin.Store(defaultDeactivationPin)
		}

		p.mu.Lock()
		rc := p.rc
		p.rc = resolverConfig
		p.mu.Unlock()
		noCustomConfig := resolverConfig.Ctrld.CustomConfig == ""
		noExcludeListChanged := true
		if rc != nil {
			slices.Sort(rc.Exclude)
			slices.Sort(resolverConfig.Exclude)
			noExcludeListChanged = slices.Equal(rc.Exclude, resolverConfig.Exclude)
		}
		if noCustomConfig && noExcludeListChanged {
			return
		}

		if noCustomConfig && !noExcludeListChanged {
			logger.Debug().Msg("exclude list changes detected, reloading...")
			p.apiReloadCh <- nil
			return
		}

		if resolverConfig.Ctrld.CustomLastUpdate > lastUpdated || forced {
			lastUpdated = time.Now().Unix()
			cfg := &ctrld.Config{}
			if err := validateCdRemoteConfig(resolverConfig, cfg); err != nil {
				logger.Warn().Err(err).Msg("skipping invalid custom config")
				if _, err := controld.UpdateCustomLastFailed(cdUID, rootCmd.Version, cdDev, true); err != nil {
					logger.Error().Err(err).Msg("could not mark custom last update failed")
				}
				return
			}
			setListenerDefaultValue(cfg)
			logger.Debug().Msg("custom config changes detected, reloading...")
			p.apiReloadCh <- cfg
		} else {
			logger.Debug().Msg("custom config does not change")
		}
	}
	for {
		select {
		case <-p.apiForceReloadCh:
			doReloadApiConfig(true, logger.With().Bool("forced", true).Logger())
		case <-ticker.C:
			doReloadApiConfig(false, logger)
		case <-p.stopCh:
			return
		}
	}
}

func (p *prog) setupUpstream(cfg *ctrld.Config) {
	localUpstreams := make([]string, 0, len(cfg.Upstream))
	ptrNameservers := make([]string, 0, len(cfg.Upstream))
	isControlDUpstream := false
	for n := range cfg.Upstream {
		uc := cfg.Upstream[n]
		sdns := uc.Type == ctrld.ResolverTypeSDNS
		uc.Init()
		if sdns {
			mainLog.Load().Debug().Msgf("initialized DNS Stamps with endpoint: %s, type: %s", uc.Endpoint, uc.Type)
		}
		isControlDUpstream = isControlDUpstream || uc.IsControlD()
		if uc.BootstrapIP == "" {
			uc.SetupBootstrapIP()
			mainLog.Load().Info().Msgf("bootstrap IPs for upstream.%s: %q", n, uc.BootstrapIPs())
		} else {
			mainLog.Load().Info().Str("bootstrap_ip", uc.BootstrapIP).Msgf("using bootstrap IP for upstream.%s", n)
		}
		uc.SetCertPool(rootCertPool)
		go uc.Ping()

		if canBeLocalUpstream(uc.Domain) {
			localUpstreams = append(localUpstreams, upstreamPrefix+n)
		}
		if uc.IsDiscoverable() {
			ptrNameservers = append(ptrNameservers, uc.Endpoint)
		}
	}
	// Self-uninstallation is ok If there is only 1 ControlD upstream, and no remote config.
	if len(cfg.Upstream) == 1 && isControlDUpstream {
		p.canSelfUninstall.Store(true)
	}
	p.localUpstreams = localUpstreams
	p.ptrNameservers = ptrNameservers
}

// run runs the ctrld main components.
//
// The reload boolean indicates that the function is run when ctrld first start
// or when ctrld receive reloading signal. Platform specifics setup is only done
// on started, mean reload is "false".
//
// The reloadCh is used to signal ctrld listeners that ctrld is going to be reloaded,
// so all listeners could be terminated and re-spawned again.
func (p *prog) run(reload bool, reloadCh chan struct{}) {
	// Wait the caller to signal that we can do our logic.
	<-p.waitCh
	if !reload {
		p.preRun()
	}
	numListeners := len(p.cfg.Listener)
	if !reload {
		p.started = make(chan struct{}, numListeners)
		if p.cs != nil {
			p.csSetDnsDone = make(chan struct{}, 1)
			p.registerControlServerHandler()
			if err := p.cs.start(); err != nil {
				mainLog.Load().Warn().Err(err).Msg("could not start control server")
			}
			mainLog.Load().Debug().Msgf("control server started: %s", p.cs.addr)
		}
	}
	p.onStartedDone = make(chan struct{})
	p.loop = make(map[string]bool)
	p.lanLoopGuard = newLoopGuard()
	p.ptrLoopGuard = newLoopGuard()
	p.cacheFlushDomainsMap = nil
	p.metricsQueryStats.Store(p.cfg.Service.MetricsQueryStats)
	if p.cfg.Service.CacheEnable {
		cacher, err := dnscache.NewLRUCache(p.cfg.Service.CacheSize)
		if err != nil {
			mainLog.Load().Error().Err(err).Msg("failed to create cacher, caching is disabled")
		} else {
			p.cache = cacher
			p.cacheFlushDomainsMap = make(map[string]struct{}, 256)
			for _, domain := range p.cfg.Service.CacheFlushDomains {
				p.cacheFlushDomainsMap[canonicalName(domain)] = struct{}{}
			}
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

	p.um = newUpstreamMonitor(p.cfg)

	if !reload {
		p.sema = &chanSemaphore{ready: make(chan struct{}, defaultSemaphoreCap)}
		if mcr := p.cfg.Service.MaxConcurrentRequests; mcr != nil {
			n := *mcr
			if n == 0 {
				p.sema = &noopSemaphore{}
			} else {
				p.sema = &chanSemaphore{ready: make(chan struct{}, n)}
			}
		}
		p.setupUpstream(p.cfg)
		p.ciTable = clientinfo.NewTable(&cfg, defaultRouteIP(), cdUID, p.ptrNameservers)
		if leaseFile := p.cfg.Service.DHCPLeaseFile; leaseFile != "" {
			mainLog.Load().Debug().Msgf("watching custom lease file: %s", leaseFile)
			format := ctrld.LeaseFileFormat(p.cfg.Service.DHCPLeaseFileFormat)
			p.ciTable.AddLeaseFile(leaseFile, format)
		}
	}

	// context for managing spawn goroutines.
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	// Newer versions of android and iOS denies permission which breaks connectivity.
	if !isMobile() && !reload {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.ciTable.Init()
			p.ciTable.RefreshLoop(ctx)
		}()
		go p.watchLinkState(ctx)
	}

	for listenerNum := range p.cfg.Listener {
		p.cfg.Listener[listenerNum].Init()
		if !reload {
			go func(listenerNum string) {
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
		go func() {
			defer func() {
				cancelFunc()
				wg.Done()
			}()
			select {
			case <-p.stopCh:
			case <-ctx.Done():
			case <-reloadCh:
			}
		}()
	}

	if !reload {
		for i := 0; i < numListeners; i++ {
			<-p.started
		}
		for _, f := range p.onStarted {
			f()
		}
	}

	close(p.onStartedDone)

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Check for possible DNS loop.
		p.checkDnsLoop()
		// Start check DNS loop ticker.
		p.checkDnsLoopTicker(ctx)
	}()

	wg.Add(1)
	// Prometheus exporter goroutine.
	go func() {
		defer wg.Done()
		p.runMetricsServer(ctx, reloadCh)
	}()

	if !reload {
		// Stop writing log to unix socket.
		consoleWriter.Out = os.Stdout
		logWriters := initLoggingWithBackup(false)
		if p.logConn != nil {
			_ = p.logConn.Close()
		}
		go p.apiConfigReload()
		p.postRun()
		p.initInternalLogging(logWriters)
	}
	wg.Wait()
}

// metricsEnabled reports whether prometheus exporter is enabled/disabled.
func (p *prog) metricsEnabled() bool {
	return p.cfg.Service.MetricsQueryStats || p.cfg.Service.MetricsListener != ""
}

func (p *prog) Stop(s service.Service) error {
	p.stopDnsWatchers()
	mainLog.Load().Debug().Msg("dns watchers stopped")
	mainLog.Load().Info().Msg("Service stopped")
	close(p.stopCh)
	if err := p.deAllocateIP(); err != nil {
		mainLog.Load().Error().Err(err).Msg("de-allocate ip failed")
		return err
	}
	return nil
}

func (p *prog) stopDnsWatchers() {
	// Ensure all DNS watchers goroutine are terminated,
	// so it won't mess up with other DNS changes.
	p.dnsWatcherClosedOnce.Do(func() {
		close(p.dnsWatcherStopCh)
	})
	p.dnsWg.Wait()
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
	setDnsOK := false
	defer func() {
		p.csSetDnsOk = setDnsOK
	}()

	if cfg.Listener == nil {
		return
	}
	if p.runningIface == "" {
		return
	}

	// allIfaces tracks whether we should set DNS for all physical interfaces.
	allIfaces := p.requiredMultiNICsConfig
	lc := cfg.FirstListener()
	if lc == nil {
		return
	}
	logger := mainLog.Load().With().Str("iface", p.runningIface).Logger()
	netIface, err := netInterface(p.runningIface)
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
		nameservers = append(nameservers, ctrld.Rfc1918Addresses()...)
	}
	if needLocalIPv6Listener() {
		nameservers = append(nameservers, "::1")
	}
	slices.Sort(nameservers)
	if err := setDNS(netIface, nameservers); err != nil {
		logger.Error().Err(err).Msgf("could not set DNS for interface")
		return
	}
	setDnsOK = true
	logger.Debug().Msg("setting DNS successfully")
	if allIfaces {
		withEachPhysicalInterfaces(netIface.Name, "set DNS", func(i *net.Interface) error {
			return setDnsIgnoreUnusableInterface(i, nameservers)
		})
	}
	if shouldWatchResolvconf() {
		servers := make([]netip.Addr, len(nameservers))
		for i := range nameservers {
			servers[i] = netip.MustParseAddr(nameservers[i])
		}
		p.dnsWg.Add(1)
		go func() {
			defer p.dnsWg.Done()
			p.watchResolvConf(netIface, servers, setResolvConf)
		}()
	}
	if p.dnsWatchdogEnabled() {
		p.dnsWg.Add(1)
		go func() {
			defer p.dnsWg.Done()
			p.dnsWatchdog(netIface, nameservers, allIfaces)
		}()
	}
}

// dnsWatchdogEnabled reports whether DNS watchdog is enabled.
func (p *prog) dnsWatchdogEnabled() bool {
	if ptr := p.cfg.Service.DnsWatchdogEnabled; ptr != nil {
		return *ptr
	}
	return true
}

// dnsWatchdogDuration returns the time duration between each DNS watchdog loop.
func (p *prog) dnsWatchdogDuration() time.Duration {
	if ptr := p.cfg.Service.DnsWatchdogInvterval; ptr != nil {
		if (*ptr).Seconds() > 0 {
			return *ptr
		}
	}
	return dnsWatchdogDefaultInterval
}

// dnsWatchdog watches for DNS changes on Darwin and Windows then re-applying ctrld's settings.
// This is only works when deactivation pin set.
func (p *prog) dnsWatchdog(iface *net.Interface, nameservers []string, allIfaces bool) {
	if !requiredMultiNICsConfig() {
		return
	}

	mainLog.Load().Debug().Msg("start DNS settings watchdog")
	ns := nameservers
	slices.Sort(ns)
	ticker := time.NewTicker(p.dnsWatchdogDuration())
	logger := mainLog.Load().With().Str("iface", iface.Name).Logger()
	for {
		select {
		case <-p.dnsWatcherStopCh:
			return
		case <-p.stopCh:
			mainLog.Load().Debug().Msg("stop dns watchdog")
			return
		case <-ticker.C:
			if p.leakingQuery.Load() || p.um.isChecking(upstreamOS) {
				return
			}
			if dnsChanged(iface, ns) {
				logger.Debug().Msg("DNS settings were changed, re-applying settings")
				if err := setDNS(iface, ns); err != nil {
					mainLog.Load().Error().Err(err).Str("iface", iface.Name).Msgf("could not re-apply DNS settings")
				}
			}
			if allIfaces {
				withEachPhysicalInterfaces(iface.Name, "", func(i *net.Interface) error {
					if dnsChanged(i, ns) {
						if err := setDnsIgnoreUnusableInterface(i, nameservers); err != nil {
							mainLog.Load().Error().Err(err).Str("iface", i.Name).Msgf("could not re-apply DNS settings")
						} else {
							mainLog.Load().Debug().Msgf("re-applying DNS for interface %q successfully", i.Name)
						}
					}
					return nil
				})
			}
		}
	}
}

func (p *prog) resetDNS() {
	if p.runningIface == "" {
		return
	}
	// See corresponding comments in (*prog).setDNS function.
	allIfaces := p.requiredMultiNICsConfig
	logger := mainLog.Load().With().Str("iface", p.runningIface).Logger()
	netIface, err := netInterface(p.runningIface)
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
	if allIfaces {
		withEachPhysicalInterfaces(netIface.Name, "reset DNS", resetDnsIgnoreUnusableInterface)
	}
}

// leakOnUpstreamFailure reports whether ctrld should leak query to OS resolver when failed to connect all upstreams.
func (p *prog) leakOnUpstreamFailure() bool {
	if ptr := p.cfg.Service.LeakOnUpstreamFailure; ptr != nil {
		return *ptr
	}
	// Default is false on routers, since this leaking is only useful for devices that move between networks.
	if router.Name() != "" {
		return false
	}
	return true
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
	windowsEHOSTUNREACH = syscall.Errno(10065)
)

func errUrlNetworkError(err error) bool {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return errNetworkError(urlErr.Err)
	}
	return false
}

func errNetworkError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Temporary() {
			return true
		}
		switch {
		case errors.Is(opErr.Err, syscall.ECONNREFUSED),
			errors.Is(opErr.Err, syscall.EINVAL),
			errors.Is(opErr.Err, syscall.ENETUNREACH),
			errors.Is(opErr.Err, windowsENETUNREACH),
			errors.Is(opErr.Err, windowsEINVAL),
			errors.Is(opErr.Err, windowsECONNREFUSED),
			errors.Is(opErr.Err, windowsEHOSTUNREACH):
			return true
		}
	}
	return false
}

// errConnectionRefused reports whether err is connection refused.
func errConnectionRefused(err error) bool {
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}
	return errors.Is(opErr.Err, syscall.ECONNREFUSED) || errors.Is(opErr.Err, windowsECONNREFUSED)
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
	dr, err := netmon.DefaultRoute()
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
	netmon.ForeachInterface(func(i netmon.Interface, prefixes []netip.Prefix) {
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

// canBeLocalUpstream reports whether the IP address can be used as a local upstream.
func canBeLocalUpstream(addr string) bool {
	if ip, err := netip.ParseAddr(addr); err == nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || tsaddr.CGNATRange().Contains(ip)
	}
	return false
}

// withEachPhysicalInterfaces runs the function f with each physical interfaces, excluding
// the interface that matches excludeIfaceName. The context is used to clarify the
// log message when error happens.
func withEachPhysicalInterfaces(excludeIfaceName, context string, f func(i *net.Interface) error) {
	validIfacesMap := validInterfacesMap()
	netmon.ForeachInterface(func(i netmon.Interface, prefixes []netip.Prefix) {
		// Skip loopback/virtual interface.
		if i.IsLoopback() || len(i.HardwareAddr) == 0 {
			return
		}
		// Skip invalid interface.
		if !validInterface(i.Interface, validIfacesMap) {
			return
		}
		netIface := i.Interface
		if err := patchNetIfaceName(netIface); err != nil {
			mainLog.Load().Debug().Err(err).Msg("failed to patch net interface name")
			return
		}
		// Skip excluded interface.
		if netIface.Name == excludeIfaceName {
			return
		}
		// TODO: investigate whether we should report this error?
		if err := f(netIface); err == nil {
			if context != "" {
				mainLog.Load().Debug().Msgf("%s for interface %q successfully", context, i.Name)
			}
		} else if !errors.Is(err, errSaveCurrentStaticDNSNotSupported) {
			mainLog.Load().Err(err).Msgf("%s for interface %q failed", context, i.Name)
		}
	})
}

// requiredMultiNicConfig reports whether ctrld needs to set/reset DNS for multiple NICs.
func requiredMultiNICsConfig() bool {
	switch runtime.GOOS {
	case "windows", "darwin":
		return true
	default:
		return false
	}
}

var errSaveCurrentStaticDNSNotSupported = errors.New("saving current DNS is not supported on this platform")

// saveCurrentStaticDNS saves the current static DNS settings for restoring later.
// Only works on Windows and Mac.
func saveCurrentStaticDNS(iface *net.Interface) error {
	switch runtime.GOOS {
	case "windows", "darwin":
	default:
		return errSaveCurrentStaticDNSNotSupported
	}
	file := savedStaticDnsSettingsFilePath(iface)
	ns, _ := currentStaticDNS(iface)
	if len(ns) == 0 {
		_ = os.Remove(file) // removing old static DNS settings
		return nil
	}
	if err := os.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
		mainLog.Load().Warn().Err(err).Msg("could not remove old static DNS settings file")
	}
	nss := strings.Join(ns, ",")
	mainLog.Load().Debug().Msgf("DNS settings for %q is static: %v, saving ...", iface.Name, nss)
	if err := os.WriteFile(file, []byte(nss), 0600); err != nil {
		mainLog.Load().Err(err).Msgf("could not save DNS settings for iface: %s", iface.Name)
		return err
	}
	mainLog.Load().Debug().Msgf("save DNS settings for interface %q successfully", iface.Name)
	return nil
}

// savedStaticDnsSettingsFilePath returns the path to saved DNS settings of the given interface.
func savedStaticDnsSettingsFilePath(iface *net.Interface) string {
	return absHomeDir(".dns_" + iface.Name)
}

// savedStaticNameservers returns the static DNS nameservers of the given interface.
//
//lint:ignore U1000 use in os_windows.go and os_darwin.go
func savedStaticNameservers(iface *net.Interface) []string {
	file := savedStaticDnsSettingsFilePath(iface)
	if data, _ := os.ReadFile(file); len(data) > 0 {
		return strings.Split(string(data), ",")
	}
	return nil
}

// dnsChanged reports whether DNS settings for given interface was changed.
// The caller must sort the nameservers before calling this function.
func dnsChanged(iface *net.Interface, nameservers []string) bool {
	curNameservers, _ := currentStaticDNS(iface)
	slices.Sort(curNameservers)
	if !slices.Equal(curNameservers, nameservers) {
		mainLog.Load().Debug().Msgf("interface %q current DNS settings: %v, expected: %v", iface.Name, curNameservers, nameservers)
		return true
	}
	return false
}

// selfUninstallCheck checks if the error dues to controld.InvalidConfigCode, perform self-uninstall then.
func selfUninstallCheck(uninstallErr error, p *prog, logger zerolog.Logger) {
	var uer *controld.ErrorResponse
	if errors.As(uninstallErr, &uer) && uer.ErrorField.Code == controld.InvalidConfigCode {
		p.stopDnsWatchers()

		// Perform self-uninstall now.
		selfUninstall(p, logger)
	}
}
