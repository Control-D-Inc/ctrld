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
	"os/exec"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Masterminds/semver/v3"
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
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
	"github.com/Control-D-Inc/ctrld/internal/router"
	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
)

const (
	defaultSemaphoreCap  = 256
	ctrldLogUnixSock     = "ctrld_start.sock"
	ctrldControlUnixSock = "ctrld_control.sock"
	// iOS unix socket name max length is 11.
	ctrldControlUnixSockMobile = "cd.sock"
	upstreamPrefix             = "upstream."
	upstreamOS                 = upstreamPrefix + "os"
	upstreamOSLocal            = upstreamOS + ".local"
	dnsWatchdogDefaultInterval = 20 * time.Second
	ctrldServiceName           = "ctrld"
)

// RecoveryReason provides context for why we are waiting for recovery.
// recovery involves removing the listener IP from the interface and
// waiting for the upstreams to work before returning
type RecoveryReason int

const (
	RecoveryReasonNetworkChange RecoveryReason = iota
	RecoveryReasonRegularFailure
	RecoveryReasonOSFailure
)

// ControlSocketName returns name for control unix socket.
func ControlSocketName() string {
	if isMobile() {
		return ctrldControlUnixSockMobile
	} else {
		return ctrldControlUnixSock
	}
}

// logf is a function variable used for logging formatted debug messages with optional arguments.
// This is used only when creating a new DNS OS configurator.
var logf = func(format string, args ...any) {
	mainLog.Load().Debug().Msgf(format, args...)
}

// noopLogf is like logf but discards formatted log messages and arguments without any processing.
//
//lint:ignore U1000 use in newLoopbackOSConfigurator
var noopLogf = func(format string, args ...any) {}

var svcConfig = &service.Config{
	Name:        ctrldServiceName,
	DisplayName: "Control-D Helper Service",
	Description: "A highly configurable, multi-protocol DNS forwarding proxy",
	Option:      service.KeyValue{},
}

var useSystemdResolved = false

type pfAnchorCheckResult uint8

const (
	pfAnchorCheckSkipped pfAnchorCheckResult = iota
	pfAnchorCheckIntact
	pfAnchorCheckRestored
	pfAnchorCheckDeferred
	pfAnchorCheckFailed
)

type prog struct {
	mu                   sync.Mutex
	waitCh               chan struct{}
	stopCh               chan struct{}
	pinCodeValidCh       chan struct{}
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
	internalWarnLogWriter     *logWriter
	internalLogSent           time.Time
	runningIface              string
	requiredMultiNICsConfig   bool
	adDomain                  string
	hasLocalDNS               bool
	runningOnDomainController bool

	selfUninstallMu       sync.Mutex
	refusedQueryCount     int
	canSelfUninstall      atomic.Bool
	checkingSelfUninstall bool

	loopMu sync.Mutex
	loop   map[string]bool

	recoveryCancelMu sync.Mutex
	recoveryCancel   context.CancelFunc
	recoveryRunning  atomic.Bool

	// recoveryDebounceTimer coalesces rapid NetworkChange recovery triggers
	// into a single handleRecovery call. Only handleRecovery is debounced —
	// all other state updates (IP, pf anchor, VPN DNS) run immediately.
	recoveryDebounceMu    sync.Mutex
	recoveryDebounceTimer *time.Timer

	// recoveryBypass is set when dns-intercept mode enters recovery.
	// When true, proxy() forwards all queries to OS/DHCP resolver
	// instead of using the normal upstream flow.
	recoveryBypass atomic.Bool

	// DNS intercept mode state (platform-specific).
	// On Windows: *wfpState, on macOS: *pfState, nil on other platforms.
	dnsInterceptState any

	// dnsInterceptMu serializes DNS intercept lifecycle transitions - start, stop and
	// the health monitor's rebuild - and guards every write to dnsInterceptState, so a
	// service stop can never interleave with a monitor-driven rebuild.
	dnsInterceptMu sync.Mutex //lint:ignore U1000 used on windows

	// dnsInterceptStopRequested is set while a stop waits for dnsInterceptMu. The
	// health and recovery flows read it as a shutdown signal and abandon their work,
	// rather than making the stop wait out their probe backoffs.
	dnsInterceptStopRequested atomic.Bool //lint:ignore U1000 used on windows

	// nrptTransitionMu makes one NRPT ownership transition - observe, mutate, signal,
	// record owner - atomic against shutdown and against another transition. It is
	// deliberately finer-grained than dnsInterceptMu: it is taken for the duration of a
	// single transition, never across the recovery flows' probe backoffs.
	nrptTransitionMu sync.Mutex //lint:ignore U1000 used on windows

	// lastTunnelIfaces tracks the tunnel set included in the last successfully loaded
	// pf anchor. Pending tunnel state is kept separately so failed PF work is retried
	// instead of being mistaken for an applied update. Protected by mu.
	lastTunnelIfaces       []string //lint:ignore U1000 used on darwin
	pendingTunnelIfaces    []string //lint:ignore U1000 used on darwin
	hasPendingTunnelIfaces bool     //lint:ignore U1000 used on darwin

	// pfStabilizing is true while we're waiting for a VPN's pf ruleset to settle.
	// While true, the watchdog and network change callbacks do NOT restore our rules.
	pfStabilizing atomic.Bool

	// pfStabilizeCancel cancels the active stabilization goroutine, if any.
	// Protected by mu.
	pfStabilizeCancel context.CancelFunc //lint:ignore U1000 used on darwin

	// pfLastRestoreTime records when we last restored our anchor (unix millis).
	// Used to detect immediate re-wipes (VPN reconnect cycle).
	pfLastRestoreTime atomic.Int64 //lint:ignore U1000 used on darwin

	// pfBackoffMultiplier tracks exponential backoff for stabilization.
	// Resets to 0 when rules survive for >60s.
	pfBackoffMultiplier atomic.Int32 //lint:ignore U1000 used on darwin

	// pfMonitorRunning ensures only one pfInterceptMonitor goroutine runs at a time.
	// When an interface appears/disappears, we spawn a monitor that probes pf
	// interception with exponential backoff and auto-heals if broken.
	pfMonitorRunning atomic.Bool //lint:ignore U1000 used on darwin

	// pfEnsureRunning ensures only one pf validation or mutation runs at a time.
	// Network callbacks, VPN exemption updates, delayed rechecks, probes, and the
	// watchdog can converge during macOS churn; concurrent pfctl/scutil work can
	// exhaust process/file limits or interleave anchor snapshots.
	pfEnsureRunning atomic.Bool //lint:ignore U1000 used on darwin

	// pfExecBackoffUntil suppresses pf anchor validation after pfctl/scutil execs
	// fail due host resource exhaustion (fork unavailable, too many open files).
	pfExecBackoffUntil atomic.Int64 //lint:ignore U1000 used on darwin

	// pfDelayedRecheckTimers coalesces delayed DNS-intercept rechecks after noisy
	// network changes. Protected by pfDelayedRecheckMu.
	pfDelayedRecheckMu     sync.Mutex    //lint:ignore U1000 used on darwin
	pfDelayedRecheckTimers []*time.Timer //lint:ignore U1000 used on darwin

	// pfIgnoredChangeLastReconcile bounds immediate pf/VPN-DNS work for noisy
	// ignored macOS network deltas. Tunnel changes bypass this limit, and the
	// existing delayed checks provide a trailing reconciliation after churn.
	pfIgnoredChangeLastReconcile atomic.Int64 //lint:ignore U1000 used on darwin

	// interceptProbes maps the domain of each pending interception probe to the channel
	// that probe waits on. A probe verifies that interception is actually translating or
	// redirecting packets, not merely present in rule text: the DNS handler looks up
	// incoming queries here and signals the matching waiter.
	//
	// It holds one entry per in-flight probe rather than a single slot, because probes do
	// overlap - the health monitor, a handback and a heal cycle can each have one out at
	// the same time - and a single slot means the last registration wins and the loser
	// waits out its timeout for a query that was answered. A false failure then triggers
	// recovery work that was not needed.
	//
	// Registrations are rare and lookups happen on every query, so the map is stored as
	// an immutable snapshot behind an atomic: readers never take a lock, writers copy
	// under interceptProbeMu.
	interceptProbes  atomic.Value // map[string]chan struct{}
	interceptProbeMu sync.Mutex   //lint:ignore U1000 written only by registerInterceptProbe, used on darwin/windows

	// VPN DNS manager for split DNS routing when intercept mode is active.
	vpnDNS *vpnDNSManager

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
				rc, err := p.fetchCDConfigBoundedByLifetime(newCfg)
				if err != nil {
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

		// Though the log configuration could not be changed during reloading, we still need to
		// process the current flags here, so runtime internal logs can be used correctly.
		processLogAndCacheFlags(v, newCfg)

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
		// In DNS-intercept mode on macOS, the DNS listener is bound once at startup and is
		// NOT re-bound on reload (see prog.run: serveDNS is started only when !reload). When
		// the configured/generated port (e.g. 127.0.0.1:53) is unavailable at startup because
		// mDNSResponder owns *:53, ctrld falls back to an alternate local port (e.g. 5354).
		// The on-disk config still declares 53, so adopting it here would revert p.cfg to a
		// port nothing is listening on, and the pf rdr rules/probes rebuilt from p.cfg would
		// target a dead port. Since a reload cannot move the running listener anyway, keep
		// p.cfg pointing at the actual bound listener. The on-disk config (written above) is
		// left unchanged. See #551.
		if dnsIntercept && runtime.GOOS == "darwin" {
			preserveBoundListeners(p.cfg.Listener, curListener)
		}
		p.mu.Unlock()

		logger.Notice().Msg("reloading config successfully")

		select {
		case p.reloadDoneCh <- struct{}{}:
		default:
		}
	}
}

// preserveBoundListeners overrides the IP/Port of each listener in newListeners with the
// actual bound address from curListeners when they differ, logging the divergence. It is used
// on config reload in DNS-intercept mode where the running listener is never re-bound, so a
// port change on disk (e.g. reverting a fallback 5354 back to the generated 53) must not be
// applied to the in-memory config that drives pf rdr rules and probes.
//
// Preservation is limited to fallback-eligible (default/unset, i.e. 127.0.0.1:53) listeners.
// An explicit, non-default listener in the reloaded config is an intentional change that must
// be applied: tryUpdateListenerConfigIntercept binds explicit listeners exactly (no fallback),
// and the control-server reload handler detects the IP/port diff to trigger a restart that
// re-binds. Reverting an explicit change here would make that comparison return 200 instead of
// 201, silently dropping the new listener. See #551.
func preserveBoundListeners(newListeners, curListeners map[string]*ctrld.ListenerConfig) {
	for n, curLc := range curListeners {
		newLc := newListeners[n]
		if newLc == nil || curLc == nil {
			continue
		}
		if newLc.IP == curLc.IP && newLc.Port == curLc.Port {
			continue
		}
		if isExplicitInterceptListener(newLc.IP, newLc.Port) {
			continue
		}
		mainLog.Load().Info().
			Str("configured", net.JoinHostPort(newLc.IP, strconv.Itoa(newLc.Port))).
			Str("actual", net.JoinHostPort(curLc.IP, strconv.Itoa(curLc.Port))).
			Msg("DNS intercept: preserving actual bound listener across reload; on-disk config port not applied to running listener")
		newLc.IP = curLc.IP
		newLc.Port = curLc.Port
	}
}

func (p *prog) preRun() {
	if iface == autoIface {
		iface = defaultIfaceName()
		p.requiredMultiNICsConfig = requiredMultiNICsConfig()
	}
	p.runningIface = iface
}

func (p *prog) postRun() {
	if !service.Interactive() {
		if runtime.GOOS == "windows" {
			isDC, roleInt := isRunningOnDomainController()
			p.runningOnDomainController = isDC
			mainLog.Load().Debug().Msgf("running on domain controller: %t, role: %d", p.runningOnDomainController, roleInt)
		}
		// A Windows organization can install a GP-owned NRPT catch-all before
		// starting ctrld. Detect that policy before resetDNS touches adapter DNS;
		// startDNSIntercept will then prove the rule functionally before adopting it.
		if !p.skipInitialDNSReset() {
			p.resetDNS(false, false)
		}
		ns := ctrld.InitializeOsResolver(false)
		mainLog.Load().Debug().Msgf("initialized OS resolver with nameservers: %v", ns)
		p.setDNS()
		p.csSetDnsDone <- struct{}{}
		close(p.csSetDnsDone)
		p.logInterfacesState()
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
	curVerStr := curVersion()
	curVer, err := semver.NewVersion(curVerStr)
	isStable := curVer != nil && curVer.Prerelease() == ""
	if err != nil || !isStable {
		l := mainLog.Load().Warn()
		if err != nil {
			l = l.Err(err)
		}
		l.Msgf("current version is not stable, skipping self-upgrade: %s", curVerStr)
	}

	doReloadApiConfig := func(forced bool, logger zerolog.Logger) {
		req := &controld.ResolverConfigRequest{
			RawUID:   cdUID,
			Version:  rootCmd.Version,
			Metadata: ctrld.SystemMetadataRuntime(context.Background()),
		}
		resolverConfig, err := controld.FetchResolverConfig(context.Background(), req, cdDev)
		selfUninstallCheck(err, p, logger)
		if err != nil {
			logger.Warn().Err(err).Msg("could not fetch resolver config")
			return
		}

		// Performing self-upgrade check for production version.
		if isStable {
			_ = selfUpgradeCheck(resolverConfig.Ctrld.VersionTarget, curVer, &logger)
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
			var cfgErr error
			if cfgErr = validateCdRemoteConfig(resolverConfig, cfg); cfgErr == nil {
				setListenerDefaultValue(cfg)
				setNetworkDefaultValue(cfg)
				cfgErr = validateConfig(cfg)
			}
			if cfgErr != nil {
				logger.Warn().Err(err).Msg("skipping invalid custom config")
				if _, err := controld.UpdateCustomLastFailed(context.Background(), cdUID, rootCmd.Version, cdDev, true); err != nil {
					logger.Error().Err(err).Msg("could not mark custom last update failed")
				}
				return
			}
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
	if domain, err := getActiveDirectoryDomain(); err == nil && domain != "" {
		mainLog.Load().Debug().Msgf("active directory domain: %s", domain)
		p.adDomain = domain
		if hasLocalDnsServerRunning() {
			mainLog.Load().Debug().Msg("local DNS server detected (Domain Controller)")
			p.hasLocalDNS = true
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
		p.setupClientInfoDiscover(defaultRouteIP())
	}

	// context for managing spawn goroutines.
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	// Newer versions of android and iOS denies permission which breaks connectivity.
	if !isMobile() && !reload {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.runClientInfoDiscover(ctx)
		}()
	}

	if !reload {
		go func() {
			// Start network monitoring
			if err := p.monitorNetworkChanges(); err != nil {
				mainLog.Load().Error().Err(err).Msg("Failed to start network monitoring")
			}
		}()
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
				mainLog.Load().Debug().Msgf("end of serveDNS listener.%s: %s", listenerNum, addr)
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
		p.initLogging(false)
		if p.logConn != nil {
			_ = p.logConn.Close()
		}
		go p.apiConfigReload()
		p.postRun()
	}
	wg.Wait()
}

// setupClientInfoDiscover performs necessary works for running client info discover.
func (p *prog) setupClientInfoDiscover(selfIP string) {
	p.ciTable = clientinfo.NewTable(&cfg, selfIP, cdUID, p.ptrNameservers)
	if leaseFile := p.cfg.Service.DHCPLeaseFile; leaseFile != "" {
		mainLog.Load().Debug().Msgf("watching custom lease file: %s", leaseFile)
		format := ctrld.LeaseFileFormat(p.cfg.Service.DHCPLeaseFileFormat)
		p.ciTable.AddLeaseFile(leaseFile, format)
	}
	if leaseFiles := dnsmasq.AdditionalLeaseFiles(); len(leaseFiles) > 0 {
		mainLog.Load().Debug().Msgf("watching additional lease files: %v", leaseFiles)
		for _, leaseFile := range leaseFiles {
			p.ciTable.AddLeaseFile(leaseFile, ctrld.Dnsmasq)
		}
	}
}

// runClientInfoDiscover runs the client info discover.
func (p *prog) runClientInfoDiscover(ctx context.Context) {
	p.ciTable.Init()
	p.ciTable.RefreshLoop(ctx)
}

// metricsEnabled reports whether prometheus exporter is enabled/disabled.
func (p *prog) metricsEnabled() bool {
	return p.cfg.Service.MetricsQueryStats || p.cfg.Service.MetricsListener != ""
}

func (p *prog) Stop(s service.Service) error {
	p.stopDnsWatchers()
	mainLog.Load().Debug().Msg("dns watchers stopped")
	for _, f := range p.onStopped {
		f()
	}
	mainLog.Load().Debug().Msg("finish running onStopped functions")
	defer func() {
		mainLog.Load().Info().Msg("Service stopped")
	}()
	if err := p.deAllocateIP(); err != nil {
		mainLog.Load().Error().Err(err).Msg("de-allocate ip failed")
		return err
	}
	if deactivationPinSet() {
		select {
		case <-p.pinCodeValidCh:
			// Allow stopping the service, pinCodeValidCh is only filled
			// after control server did validate the pin code.
		case <-time.After(time.Millisecond * 100):
			// No valid pin code was checked, that mean we are stopping
			// because of OS signal sent directly from someone else.
			// In this case, restarting ctrld service by ourselves.
			mainLog.Load().Debug().Msgf("receiving stopping signal without valid pin code")
			mainLog.Load().Debug().Msgf("self restarting ctrld service")
			if exe, err := os.Executable(); err == nil {
				cmd := exec.Command(exe, "restart")
				cmd.SysProcAttr = sysProcAttrForDetachedChildProcess()
				if err := cmd.Start(); err != nil {
					mainLog.Load().Error().Err(err).Msg("failed to run self restart command")
				}
			} else {
				mainLog.Load().Error().Err(err).Msg("failed to self restart ctrld service")
			}
			os.Exit(deactivationPinInvalidExitCode)
		}
	}
	close(p.stopCh)
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

// Seams for the intercept-start failure lifecycle. Choosing between the interface-DNS
// fallback and refusing it has side effects - restoring the host's DNS, then
// terminating - which a test has to observe without reconfiguring the host or exiting
// the test binary. The intercept start itself is indirected for the same reason: it is
// the real platform interceptor, which on macOS mutates pf and on Windows installs an
// NRPT rule, so a test of what happens *after* it fails must not be the thing that
// runs it.
var (
	localResolverIPFn       = router.LocalResolverIP
	startDNSInterceptFn     = (*prog).startDNSIntercept
	setDnsForRunningIfaceFn = (*prog).setDnsForRunningIface
	resetDNSFn              = (*prog).resetDNS
	refuseFallbackFatal     = func(format string, v ...any) {
		mainLog.Load().Fatal().Msgf(format, v...)
	}
)

// interfaceDNSFallbackViable reports whether the interface-DNS fallback can actually
// direct queries to ctrld's listener.
//
// Interface DNS names a resolver by IP and has no port field - true of macOS interface
// settings and of Windows NRPT rules - so pointing the system straight at a listener
// that did not bind :53 sends queries to whatever owns :53 instead, and that resolver's
// upstream is ctrld's address: a loop, not a fallback.
//
// A nil or portless listener is treated as viable: the port is resolved elsewhere and
// defaults to 53, so there is nothing to refuse yet.
//
// A non-53 listener is still viable where a local resolver owns :53 and forwards to
// ctrld's port. That is the arrangement on the router platforms with a dnsmasq of their
// own: ctrld writes "server=<listener ip>#<listener port>", so the forward follows
// whatever port ctrld actually bound. setDNS then points the interface at that resolver
// rather than at the listener - see the lc.Port != 53 case there, which this mirrors.
// Refusing on port alone would turn a working configuration into a startup failure on
// those routers.
func interfaceDNSFallbackViable(lc *ctrld.ListenerConfig, localResolverIP string) bool {
	return lc == nil || lc.Port == 0 || lc.Port == 53 || localResolverIP != ""
}

func (p *prog) setDNS() {
	setDnsOK := false
	defer func() {
		p.csSetDnsOk = setDnsOK
	}()

	// Validate and resolve intercept mode.
	// CLI flag (--intercept-mode) takes priority over config file.
	// Valid values: "" (use config), "off" (explicitly disable), "dns" (with VPN
	// split routing), and "hard" (all DNS through ctrld).
	if interceptMode != "" && !validInterceptMode(interceptMode) {
		mainLog.Load().Fatal().Msgf("invalid --intercept-mode value %q: must be 'off', 'dns', or 'hard'", interceptMode)
	}
	if interceptMode == "" {
		interceptMode = p.configuredInterceptMode()
		if interceptMode != "" && interceptMode != "off" {
			mainLog.Load().Info().Msgf("Intercept mode enabled via config (intercept_mode = %q)", interceptMode)
		}
	}

	// Derive convenience bools from interceptMode.
	switch interceptMode {
	case "dns":
		dnsIntercept = true
	case "hard":
		dnsIntercept = true
		hardIntercept = true
	}

	// DNS intercept mode: use OS-level packet interception (WFP/pf) instead of
	// modifying interface DNS settings. This eliminates race conditions with VPN
	// software that also manages DNS. See issue #489.
	if dnsIntercept {
		if err := startDNSInterceptFn(p); err != nil {
			// This check comes first: it is the one failure where DNS already works
			// without ctrld touching anything else, so neither the refusal below nor the
			// fallback applies.
			//
			// An externally managed rule was proved - by probe, not by registry shape -
			// to be routing DNS to this listener. Falling through would rewrite adapter
			// DNS after explicitly preserving it, and DNS still works, so stop here.
			//
			// Only a verified route earns this. A rule that merely exists does not: if it
			// is not actually routing and intercept failed too, the machine would be left
			// with no NRPT, no WFP and no adapter fallback - that is, unfiltered - so
			// every other failure takes the paths below.
			if interceptFailedUnderExternalDNSPolicy(err) {
				if interceptFailedWithVerifiedExternalDNS(err) {
					mainLog.Load().Error().Err(err).Msg("DNS intercept mode failed but externally managed DNS policy is verified routing to ctrld — not falling back to interface DNS settings")
				} else {
					// Owned by external policy but not proved to route: DNS is not
					// reaching ctrld. Adapter DNS still stays as the organization set it,
					// and setDnsOK stays false, so this start reports as failed until a
					// probe succeeds.
					mainLog.Load().Error().Err(err).Msg("DNS intercept mode failed and externally managed DNS policy is not routing to ctrld — leaving interface DNS settings untouched; the service is not ready")
				}
				return
			}
			// Interface DNS cannot express a port: macOS interface settings and Windows
			// NRPT rules both name a resolver by IP alone. So it is only a usable
			// fallback when the listener actually bound :53. When something else owns
			// :53 - mDNSResponder on macOS, which is the whole reason the :5354 fallback
			// exists - pointing the system at 127.0.0.1 hands queries to that other
			// resolver, whose own upstream is now ctrld's address. That is a resolution
			// loop, not degraded operation: a healthy ctrld listener nothing on the host
			// can reach, no working DNS, and no recovery short of stopping the service.
			//
			// Refuse instead, after putting the host's own DNS back. A visible startup
			// failure beats DNS that is broken by design, and it stops a fallback that
			// cannot work from quietly undoing the fail-closed verification above.
			if lc := cfg.FirstListener(); !interfaceDNSFallbackViable(lc, localResolverIPFn()) {
				mainLog.Load().Error().Err(err).Msgf("DNS intercept mode failed with the listener on port %d", lc.Port)
				// Leave the host resolvable: restore static settings or DHCP rather than
				// exiting with an interface still pointed at a ctrld that is not serving.
				resetDNSFn(p, false, true)
				refuseFallbackFatal("Refusing to fall back to interface DNS: it cannot direct queries to %s:%d, which would leave this host with no working resolver. Free port 53 for ctrld, or resolve the intercept failure, then start again.", lc.IP, lc.Port)
				// Unreachable in production - the line above exits - but returning
				// explicitly keeps the refusal from depending on that, so nothing can
				// fall through to installing the fallback this just rejected.
				return
			}
			mainLog.Load().Error().Err(err).Msg("DNS intercept mode failed — falling back to interface DNS settings")
			// Fall through to traditional setDNS behavior.
		} else {
			if hardIntercept {
				mainLog.Load().Info().Msg("Hard intercept mode active — all DNS through ctrld, no VPN split routing")
			} else {
				mainLog.Load().Info().Msg("DNS intercept mode active — skipping interface DNS configuration and watchdog")

				// Initialize VPN DNS manager for split DNS routing.
				// Discovers search domains from virtual/VPN interfaces and forwards
				// matching queries to the DNS server on that interface.
				// Skipped in --intercept-mode hard where all DNS goes through ctrld.
				p.vpnDNS = newVPNDNSManager(p.exemptVPNDNSServers)
				p.vpnDNS.Refresh(true)
			}

			setDnsOK = true
			return
		}
	}

	if cfg.Listener == nil {
		return
	}
	lc := cfg.FirstListener()
	if lc == nil {
		return
	}
	ns := lc.IP
	switch {
	case lc.IsDirectDnsListener():
		// If ctrld is direct listener, use 127.0.0.1 as nameserver.
		ns = "127.0.0.1"
	case lc.Port != 53:
		ns = "127.0.0.1"
		if resolver := localResolverIPFn(); resolver != "" {
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
	if needLocalIPv6Listener(p.cfg.Service.InterceptMode) {
		nameservers = append(nameservers, "::1")
	}

	slices.Sort(nameservers)

	netIfaceName := ""
	netIface := setDnsForRunningIfaceFn(p, nameservers)
	if netIface != nil {
		netIfaceName = netIface.Name
	}
	setDnsOK = true

	if p.requiredMultiNICsConfig {
		withEachPhysicalInterfaces(netIfaceName, "set DNS", func(i *net.Interface) error {
			return setDnsIgnoreUnusableInterface(i, nameservers)
		})
	}
	// resolvconf file is only useful when we have default route interface,
	// then set DNS on this interface will push change to /etc/resolv.conf file.
	if netIface != nil && shouldWatchResolvconf() {
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
			p.dnsWatchdog(netIface, nameservers)
		}()
	}
}

// configuredInterceptMode resolves the service's effective intercept mode without
// mutating package state. Platform startup preflights use the same precedence as
// setDNS so they do not make adapter-DNS decisions from a different mode value.
func (p *prog) configuredInterceptMode() string {
	im := interceptMode
	if im == "" || im == "off" {
		im = p.cfg.Service.InterceptMode
	}
	return im
}

func (p *prog) setDnsForRunningIface(nameservers []string) (runningIface *net.Interface) {
	if p.runningIface == "" {
		return
	}

	logger := mainLog.Load().With().Str("iface", p.runningIface).Logger()

	const maxDNSRetryAttempts = 3
	const retryDelay = 1 * time.Second
	var netIface *net.Interface
	var err error
	for attempt := 1; attempt <= maxDNSRetryAttempts; attempt++ {
		netIface, err = netInterface(p.runningIface)
		if err == nil {
			break
		}
		if attempt < maxDNSRetryAttempts {
			// Try to find a different working interface
			newIface := findWorkingInterface(p.runningIface)
			if newIface != p.runningIface {
				p.runningIface = newIface
				logger = mainLog.Load().With().Str("iface", p.runningIface).Logger()
				logger.Info().Msg("switched to new interface")
				continue
			}

			logger.Warn().Err(err).Int("attempt", attempt).Msg("could not get interface, retrying...")
			time.Sleep(retryDelay)
			continue
		}
		logger.Error().Err(err).Msg("could not get interface after all attempts")
		return
	}
	if err := setupNetworkManager(); err != nil {
		logger.Error().Err(err).Msg("could not patch NetworkManager")
		return
	}

	runningIface = netIface
	logger.Debug().Msg("setting DNS for interface")
	if err := setDNS(netIface, nameservers); err != nil {
		logger.Error().Err(err).Msgf("could not set DNS for interface")
		return
	}
	logger.Debug().Msg("setting DNS successfully")
	return
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
func (p *prog) dnsWatchdog(iface *net.Interface, nameservers []string) {
	if !requiredMultiNICsConfig() {
		return
	}

	mainLog.Load().Debug().Msg("start DNS settings watchdog")

	ns := nameservers
	slices.Sort(ns)
	ticker := time.NewTicker(p.dnsWatchdogDuration())

	for {
		select {
		case <-p.dnsWatcherStopCh:
			return
		case <-p.stopCh:
			mainLog.Load().Debug().Msg("stop dns watchdog")
			return
		case <-ticker.C:
			if p.recoveryRunning.Load() {
				return
			}
			if dnsChanged(iface, ns) {
				mainLog.Load().Debug().Msg("DNS settings were changed, re-applying settings")
				// Check if the interface already has static DNS servers configured.
				// currentStaticDNS is an OS-dependent helper that returns the current static DNS.
				staticDNS, err := currentStaticDNS(iface)
				if err != nil {
					mainLog.Load().Debug().Err(err).Msgf("failed to get static DNS for interface %s", iface.Name)
				} else if len(staticDNS) > 0 {
					//filter out loopback addresses
					staticDNS = slices.DeleteFunc(staticDNS, func(s string) bool {
						return net.ParseIP(s).IsLoopback()
					})
					// if we have a static config and no saved IPs already, save them
					if len(staticDNS) > 0 && len(savedStaticNameservers(iface)) == 0 {
						// Save these static DNS values so that they can be restored later.
						if err := saveCurrentStaticDNS(iface); err != nil {
							mainLog.Load().Debug().Err(err).Msgf("failed to save static DNS for interface %s", iface.Name)
						}
					}
				}
				if err := setDNS(iface, ns); err != nil {
					mainLog.Load().Error().Err(err).Str("iface", iface.Name).Msgf("could not re-apply DNS settings")
				}
			}
			if p.requiredMultiNICsConfig {
				ifaceName := ""
				if iface != nil {
					ifaceName = iface.Name
				}
				withEachPhysicalInterfaces(ifaceName, "", func(i *net.Interface) error {
					if dnsChanged(i, ns) {

						// Check if the interface already has static DNS servers configured.
						// currentStaticDNS is an OS-dependent helper that returns the current static DNS.
						staticDNS, err := currentStaticDNS(i)
						if err != nil {
							mainLog.Load().Debug().Err(err).Msgf("failed to get static DNS for interface %s", i.Name)
						} else if len(staticDNS) > 0 {
							//filter out loopback addresses
							staticDNS = slices.DeleteFunc(staticDNS, func(s string) bool {
								return net.ParseIP(s).IsLoopback()
							})
							// if we have a static config and no saved IPs already, save them
							if len(staticDNS) > 0 && len(savedStaticNameservers(i)) == 0 {
								// Save these static DNS values so that they can be restored later.
								if err := saveCurrentStaticDNS(i); err != nil {
									mainLog.Load().Debug().Err(err).Msgf("failed to save static DNS for interface %s", i.Name)
								}
							}
						}

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

// resetDNS performs a DNS reset for all interfaces.
// In DNS intercept mode, this tears down the WFP/pf filters instead.
func (p *prog) resetDNS(isStart bool, restoreStatic bool) {
	if dnsIntercept && p.dnsInterceptState != nil {
		if err := p.stopDNSIntercept(); err != nil {
			mainLog.Load().Error().Err(err).Msg("Failed to stop DNS intercept mode during reset")
		}

		// Clean up VPN DNS manager
		p.vpnDNS = nil

		return
	}
	netIfaceName := ""
	if netIface := p.resetDNSForRunningIface(isStart, restoreStatic); netIface != nil {
		netIfaceName = netIface.Name
	}
	// See corresponding comments in (*prog).setDNS function.
	if p.requiredMultiNICsConfig {
		withEachPhysicalInterfaces(netIfaceName, "reset DNS", resetDnsIgnoreUnusableInterface)
	}
}

// resetDNSForRunningIface performs a DNS reset on the running interface.
// The parameter isStart indicates whether this is being called as part of a start (or restart)
// command. When true, we check if the current static DNS configuration already differs from the
// service listener (127.0.0.1). If so, we assume that an admin has manually changed the interface's
// static DNS settings and we do not override them using the potentially out-of-date saved file.
// Otherwise, we restore the saved configuration (if any) or reset to DHCP.
func (p *prog) resetDNSForRunningIface(isStart bool, restoreStatic bool) (runningIface *net.Interface) {
	if p.runningIface == "" {
		mainLog.Load().Debug().Msg("no running interface, skipping resetDNS")
		return
	}
	logger := mainLog.Load().With().Str("iface", p.runningIface).Logger()
	netIface, err := netInterface(p.runningIface)
	if err != nil {
		logger.Error().Err(err).Msg("could not get interface")
		return
	}
	runningIface = netIface
	if err := restoreNetworkManager(); err != nil {
		logger.Error().Err(err).Msg("could not restore NetworkManager")
		return
	}

	// If starting, check the current static DNS configuration.
	if isStart {
		current, err := currentStaticDNS(netIface)
		if err != nil {
			logger.Warn().Err(err).Msg("unable to obtain current static DNS configuration; proceeding to restore saved config")
		} else if len(current) > 0 {
			// If any static DNS value is not our own listener, assume an admin override.
			hasManualConfig := false
			for _, ns := range current {
				if ns != "127.0.0.1" && ns != "::1" {
					hasManualConfig = true
					break
				}
			}
			if hasManualConfig {
				logger.Debug().Msgf("Detected manual DNS configuration on interface %q: %v; not overriding with saved configuration", netIface.Name, current)
				return
			}
		}
	}

	// Default logic: if there is a saved static DNS configuration, restore it.
	saved := savedStaticNameservers(netIface)
	if len(saved) > 0 && restoreStatic {
		logger.Debug().Msgf("Restoring interface %q from saved static config: %v", netIface.Name, saved)
		if err := setDNS(netIface, saved); err != nil {
			logger.Error().Err(err).Msgf("failed to restore static DNS config on interface %q", netIface.Name)
			return
		}
	} else {
		logger.Debug().Msgf("No saved static DNS config for interface %q; resetting to DHCP", netIface.Name)
		if err := resetDNS(netIface); err != nil {
			logger.Error().Err(err).Msgf("failed to reset DNS to DHCP on interface %q", netIface.Name)
			return
		}
	}
	return
}

func (p *prog) logInterfacesState() {
	withEachPhysicalInterfaces("", "", func(i *net.Interface) error {
		addrs, err := i.Addrs()
		if err != nil {
			mainLog.Load().Warn().Str("interface", i.Name).Err(err).Msg("failed to get addresses")
		}
		nss, err := currentStaticDNS(i)
		if err != nil {
			mainLog.Load().Warn().Str("interface", i.Name).Err(err).Msg("failed to get DNS")
		}
		if len(nss) == 0 {
			nss = currentDNS(i)
		}
		mainLog.Load().Debug().
			Any("addrs", addrs).
			Strs("nameservers", nss).
			Int("index", i.Index).
			Msgf("interface state: %s", i.Name)
		return nil
	})
}

// findWorkingInterface looks for a network interface with a valid IP configuration
func findWorkingInterface(currentIface string) string {
	// Helper to check if IP is valid (not link-local)
	isValidIP := func(ip net.IP) bool {
		return ip != nil &&
			!ip.IsLinkLocalUnicast() &&
			!ip.IsLinkLocalMulticast() &&
			!ip.IsLoopback() &&
			!ip.IsUnspecified()
	}

	// Helper to check if interface has valid IP configuration
	hasValidIPConfig := func(iface *net.Interface) bool {
		if iface == nil || iface.Flags&net.FlagUp == 0 {
			return false
		}

		addrs, err := iface.Addrs()
		if err != nil {
			mainLog.Load().Debug().
				Str("interface", iface.Name).
				Err(err).
				Msg("failed to get interface addresses")
			return false
		}

		for _, addr := range addrs {
			// Check for IP network
			if ipNet, ok := addr.(*net.IPNet); ok {
				if isValidIP(ipNet.IP) {
					return true
				}
			}
		}
		return false
	}

	// Get default route interface
	defaultRoute, err := netmon.DefaultRoute()
	if err != nil {
		mainLog.Load().Debug().
			Err(err).
			Msg("failed to get default route")
	} else {
		mainLog.Load().Debug().
			Str("default_route_iface", defaultRoute.InterfaceName).
			Msg("found default route")
	}

	// Get all interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to list network interfaces")
		return currentIface // Return current interface as fallback
	}

	var firstWorkingIface string
	var currentIfaceValid bool

	// Single pass through interfaces
	for _, iface := range ifaces {
		// Must be physical (has MAC address)
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		// Skip interfaces that are:
		// - Loopback
		// - Not up
		// - Point-to-point (like VPN tunnels)
		if iface.Flags&net.FlagLoopback != 0 ||
			iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagPointToPoint != 0 {
			continue
		}

		if !hasValidIPConfig(&iface) {
			continue
		}

		// Found working physical interface
		if err == nil && defaultRoute.InterfaceName == iface.Name {
			// Found interface with default route - use it immediately
			mainLog.Load().Info().
				Str("old_iface", currentIface).
				Str("new_iface", iface.Name).
				Msg("switching to interface with default route")
			return iface.Name
		}

		// Keep track of first working interface as fallback
		if firstWorkingIface == "" {
			firstWorkingIface = iface.Name
		}

		// Check if this is our current interface
		if iface.Name == currentIface {
			currentIfaceValid = true
		}
	}

	// Return interfaces in order of preference:
	// 1. Current interface if it's still valid
	if currentIfaceValid {
		mainLog.Load().Debug().
			Str("interface", currentIface).
			Msg("keeping current interface")
		return currentIface
	}

	// 2. First working interface found
	if firstWorkingIface != "" {
		mainLog.Load().Info().
			Str("old_iface", currentIface).
			Str("new_iface", firstWorkingIface).
			Msg("switching to first working physical interface")
		return firstWorkingIface
	}

	// 3. Fall back to current interface if nothing else works
	mainLog.Load().Warn().
		Str("current_iface", currentIface).
		Msg("no working physical interface found, keeping current")
	return currentIface
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

// The unreachable winsock errnos (ENETUNREACH/EHOSTUNREACH) are matched via
// ctrldnet.IsUnreachable, which owns their definitions.
//
// https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2
var (
	windowsECONNREFUSED = syscall.Errno(10061)
	windowsEINVAL       = syscall.Errno(10022)
	windowsEADDRINUSE   = syscall.Errno(10048)
)

// errUrlNetworkError reports whether a failed HTTP attempt is worth retrying.
//
// The two-attempt paths compose one *url.Error per attempt - hostname first, then the
// direct-IP fallback - so this walks them in order rather than classifying only the first
// one errors.As happens to find. Each attempt can say one of three things:
//
//   - retryable (unreachable, refused, temporary): retry, whichever attempt said it;
//   - a name-resolution failure: no verdict. Only the hostname attempt resolves DNS, and
//     at boot behind a captive portal or before the router's forwarder is up it fails
//     this way while the network is merely not ready yet. Consult the next attempt;
//   - anything else, notably a locally denied socket (WSAEACCES from a firewall blocking
//     ctrld): definitive. Stop, because retrying cannot clear it - the Firewall Mode
//     incident spent 256 retry cycles against filters that were never going to clear.
func errUrlNetworkError(err error) bool {
	for _, attempt := range attemptErrors(err) {
		var urlErr *url.Error
		if !errors.As(attempt, &urlErr) {
			continue
		}
		switch {
		case errNetworkError(urlErr.Err):
			return true
		case errDNSResolutionFailure(urlErr.Err):
			// Neutral; let a later attempt decide.
		default:
			return false
		}
	}
	return false
}

// attemptErrors returns the per-attempt errors recorded in err, in the order they were
// tried. A composed fallback error wraps one per attempt; anything else is a single
// attempt.
func attemptErrors(err error) []error {
	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		return multi.Unwrap()
	}
	return []error{err}
}

// errDNSResolutionFailure reports whether err is a name-resolution failure. Go marks a
// *net.DNSError as temporary only for socket failures that reached the server, so a
// SERVFAIL or "no such host" answer is not temporary - but it is also not evidence that
// retrying is pointless, which is why callers treat it as no verdict.
func errDNSResolutionFailure(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}

func errNetworkError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Temporary() {
			return true
		}
		if ctrldnet.IsUnreachable(err) {
			return true
		}
		switch {
		case errors.Is(opErr.Err, syscall.ECONNREFUSED),
			errors.Is(opErr.Err, syscall.EINVAL),
			errors.Is(opErr.Err, windowsEINVAL),
			errors.Is(opErr.Err, windowsECONNREFUSED):
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
		// Skip loopback/virtual/down interface.
		if i.IsLoopback() || len(i.HardwareAddr) == 0 {
			return
		}
		// Skip invalid interface.
		if !validInterface(i.Interface, validIfacesMap) {
			return
		}
		netIface := i.Interface
		if patched, err := patchNetIfaceName(netIface); err != nil {
			mainLog.Load().Debug().Err(err).Msg("failed to patch net interface name")
			return
		} else if !patched {
			// The interface is not functional, skipping.
			return
		}
		// Skip excluded interface.
		if netIface.Name == excludeIfaceName {
			return
		}
		// TODO: investigate whether we should report this error?
		if err := f(netIface); err == nil {
			if context != "" {
				mainLog.Load().Debug().Msgf("Ran %s for interface %q successfully", context, i.Name)
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
	if iface == nil {
		mainLog.Load().Debug().Msg("could not save current static DNS settings for nil interface")
		return nil
	}
	switch runtime.GOOS {
	case "windows", "darwin":
	default:
		return errSaveCurrentStaticDNSNotSupported
	}
	file := savedStaticDnsSettingsFilePath(iface)
	ns, err := currentStaticDNS(iface)
	if err != nil {
		mainLog.Load().Warn().Err(err).Msgf("could not get current static DNS settings for %q", iface.Name)
		return err
	}
	if len(ns) == 0 {
		mainLog.Load().Debug().Msgf("no static DNS settings for %q, removing old static DNS settings file", iface.Name)
		_ = os.Remove(file) // removing old static DNS settings
		return nil
	}
	//filter out loopback addresses
	ns = slices.DeleteFunc(ns, func(s string) bool {
		return net.ParseIP(s).IsLoopback()
	})
	//if we now have no static DNS settings and the file already exists
	// return and do not save the file
	if len(ns) == 0 {
		mainLog.Load().Debug().Msgf("loopback on %q, skipping saving static DNS settings", iface.Name)
		return nil
	}
	if err := os.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
		mainLog.Load().Warn().Err(err).Msgf("could not remove old static DNS settings file: %s", file)
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
	if iface == nil {
		return ""
	}
	return absHomeDir(".dns_" + iface.Name)
}

// savedStaticNameservers returns the static DNS nameservers of the given interface.
//
//lint:ignore U1000 use in os_windows.go and os_darwin.go
func savedStaticNameservers(iface *net.Interface) []string {
	if iface == nil {
		mainLog.Load().Debug().Msg("could not get saved static DNS settings for nil interface")
		return nil
	}
	file := savedStaticDnsSettingsFilePath(iface)
	if data, _ := os.ReadFile(file); len(data) > 0 {
		saveValues := strings.Split(string(data), ",")
		returnValues := []string{}
		// check each one, if its in loopback range, remove it
		for _, v := range saveValues {
			if net.ParseIP(v).IsLoopback() {
				continue
			}
			returnValues = append(returnValues, v)
		}
		return returnValues
	}
	return nil
}

// dnsChanged reports whether DNS settings for given interface was changed.
// It returns false for a nil iface.
//
// The caller must sort the nameservers before calling this function.
func dnsChanged(iface *net.Interface, nameservers []string) bool {
	if iface == nil {
		return false
	}
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

// shouldUpgrade checks if the version target vt is greater than the current one cv.
// Major version upgrades are not allowed to prevent breaking changes.
//
// The callers must ensure curVer and logger are non-nil.
// Returns true if upgrade is allowed, false otherwise.
func shouldUpgrade(vt string, cv *semver.Version, logger *zerolog.Logger) bool {
	if vt == "" {
		logger.Debug().Msg("no version target set, skipped checking self-upgrade")
		return false
	}
	vts := vt
	if !strings.HasPrefix(vts, "v") {
		vts = "v" + vts
	}
	targetVer, err := semver.NewVersion(vts)
	if err != nil {
		logger.Warn().Err(err).Msgf("invalid target version, skipped self-upgrade: %s", vt)
		return false
	}

	// Prevent major version upgrades to avoid breaking changes
	if targetVer.Major() != cv.Major() {
		logger.Warn().
			Str("target", vt).
			Str("current", cv.String()).
			Msgf("major version upgrade not allowed (target: %d, current: %d), skipped self-upgrade", targetVer.Major(), cv.Major())
		return false
	}

	if !targetVer.GreaterThan(cv) {
		logger.Debug().
			Str("target", vt).
			Str("current", cv.String()).
			Msgf("target version is not greater than current one, skipped self-upgrade")
		return false
	}

	return true
}

// newUpgradeCmd builds the detached command used to self-upgrade. It is a
// package-level variable so tests can stub it. With the real implementation a
// *test* binary would re-exec itself — os.Executable() is the test binary, and
// because `go test` stops flag parsing at the first positional arg ("upgrade")
// it ignores the args and re-runs the entire suite. That child hits the same
// upgrade test and spawns another child, recursively: a fork bomb of detached
// processes that pins the host and locks the test binary's image file.
var newUpgradeCmd = func(exe string) *exec.Cmd {
	cmd := exec.Command(exe, "upgrade", "prod", "-vv")
	cmd.SysProcAttr = sysProcAttrForDetachedChildProcess()
	return cmd
}

// performUpgrade executes the self-upgrade command.
// Returns true if upgrade was initiated successfully, false otherwise.
func performUpgrade(vt string) bool {
	exe, err := os.Executable()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to get executable path, skipped self-upgrade")
		return false
	}
	cmd := newUpgradeCmd(exe)
	if err := cmd.Start(); err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to start self-upgrade")
		return false
	}
	mainLog.Load().Debug().Msgf("self-upgrade triggered, version target: %s", vt)
	return true
}

// selfUpgradeCheck checks if the version target vt is greater
// than the current one cv, perform self-upgrade then.
// Major version upgrades are not allowed to prevent breaking changes.
//
// The callers must ensure curVer and logger are non-nil.
// Returns true if upgrade is allowed and should proceed, false otherwise.
func selfUpgradeCheck(vt string, cv *semver.Version, logger *zerolog.Logger) bool {
	if shouldUpgrade(vt, cv, logger) {
		return performUpgrade(vt)
	}
	return false
}

// leakOnUpstreamFailure reports whether ctrld should initiate a recovery flow
// when upstream failures occur.
func (p *prog) leakOnUpstreamFailure() bool {
	if ptr := p.cfg.Service.LeakOnUpstreamFailure; ptr != nil {
		return *ptr
	}
	// Default is false on routers, since this leaking is only useful for devices that move between networks.
	if router.Name() != "" {
		return false
	}
	// if we are running on ADDC, we should not leak on upstream failure
	if p.runningOnDomainController {
		return false
	}
	return true
}

// Domain controller role values from Win32_ComputerSystem
// https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem
const (
	BackupDomainController  = 4
	PrimaryDomainController = 5
)

// isRunningOnDomainController checks if the current machine is a domain controller
// by querying the DomainRole property from Win32_ComputerSystem via WMI.
func isRunningOnDomainController() (bool, int) {
	if runtime.GOOS != "windows" {
		return false, 0
	}
	return isRunningOnDomainControllerWindows()
}
