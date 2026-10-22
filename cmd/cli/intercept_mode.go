package cli

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld"
)

// interceptByDefault reports whether this host intercepts DNS when no mode is
// selected: the supported desktop platforms, macOS and Windows workstation
// editions. Windows Server is excluded: a server, a domain controller running
// its own DNS server in particular, keeps interface DNS mode unless intercept
// is selected explicitly, which still works there. Elsewhere intercept is not
// supported at all. It is a variable so tests pin both behaviors on any host.
var interceptByDefault = interceptByDefaultOn(runtime.GOOS, ctrld.IsDesktopPlatform())

// interceptByDefaultOn is interceptByDefault for a given GOOS. iOS builds the
// darwin files, so ctrld.IsDesktopPlatform reports it as a desktop, but it has
// no pf to intercept with.
func interceptByDefaultOn(goos string, desktop bool) bool {
	return desktop && goos != "ios"
}

// interceptBlockedByOSUpstream reports whether intercept mode cannot serve an
// OS-resolver upstream on this platform. On macOS, pf redirects ctrld's own
// port-53 queries to such an upstream back to ctrld. It is a variable so tests
// pin both behaviors on any host.
var interceptBlockedByOSUpstream = runtime.GOOS == "darwin" || runtime.GOOS == "ios"

// interceptConfigBlocker reports why cfg cannot run in intercept mode on this
// platform, or nil. An explicit selection of intercept mode fails on it in
// validateDNSIntercept; the default does not select intercept mode for it.
func interceptConfigBlocker(cfg *ctrld.Config) error {
	if !interceptBlockedByOSUpstream || cfg == nil {
		return nil
	}
	for name, uc := range cfg.Upstream {
		if uc != nil && (uc.Type == ctrld.ResolverTypeOS || uc.Type == "") {
			return fmt.Errorf("dns intercept: upstream %q uses OS resolver (port 53) which would create "+
				"a redirect loop with pf. Use DoH upstreams (--proto doh) with dns-intercept mode", name)
		}
	}
	return nil
}

// Where the effective intercept mode came from, for logs and status output.
const (
	interceptModeSourceFlag    = "flag"
	interceptModeSourceConfig  = "config"
	interceptModeSourceDefault = "default"
)

// interceptModeSource records where setDNS took the effective mode from. setDNS
// replaces interceptMode with the resolved value, so the flag alone no longer
// tells an explicit selection from the platform default afterwards.
var interceptModeSource string

// runningAsService reports whether this process runs as the installed service,
// started by the OS service manager, rather than interactively. It is a
// variable so tests pin both behaviors.
var runningAsService = func() bool { return !service.Interactive() }

// interceptModeDefaultFlag marks a service that "ctrld start" installed with
// no intercept mode selected: the service applies the platform default
// (defaultInterceptMode). It is recorded as one --intercept-mode-default=true
// argument. Every ctrld run since 2023 ignores unknown flags, so the marker is
// safe for a downgraded binary, and the inline value keeps an older parser
// from taking the next argument as its value.
const interceptModeDefaultFlag = "--intercept-mode-default"

// interceptModeDefault is set by the hidden --intercept-mode-default flag of
// "ctrld run".
var interceptModeDefault bool

// errInterceptDefaultLegacyService is why an installed service that records
// no intercept mode keeps interface DNS mode.
var errInterceptDefaultLegacyService = errors.New("the service records no intercept mode, so it was installed " +
	"before dns intercept mode became the default; keeping interface DNS mode")

// platformDefaultInterceptMode is the mode a new installation, or a foreground
// run, uses for cfg when neither --intercept-mode nor service.intercept_mode
// selects one: "dns" on the supported desktop platforms, and none (interface
// DNS mode) elsewhere, so Windows Server keeps its DNS setup and an
// unsupported platform never enters an intercept start that is known to fail.
//
// The default also steps back to interface DNS mode for a config that cannot
// run in intercept mode, and returns the reason: a config that worked in
// interface DNS mode must not start failing because the default changed.
func platformDefaultInterceptMode(cfg *ctrld.Config) (mode string, blocked error) {
	if !interceptByDefault {
		return "", nil
	}
	if err := interceptConfigBlocker(cfg); err != nil {
		return "", err
	}
	return "dns", nil
}

// defaultInterceptMode is the mode this process uses for cfg when neither
// --intercept-mode nor service.intercept_mode selects one. It ranks below both,
// so a mode in a Control D custom config or a --base64_config still wins.
//
// An installed service gets the platform default only if "ctrld start"
// marked it as a fresh install with --intercept-mode-default
// (installInterceptMode). A service with neither a mode nor the marker was
// installed before dns intercept mode became the default, in what was then
// Standard mode. It keeps interface DNS mode: an upgrade, whichever path
// performs it, must not silently switch an existing Standard install to
// intercept mode.
//
// The default is decided here, against the config the service runs with,
// which in Control D mode is only known once the service fetched it.
func defaultInterceptMode(cfg *ctrld.Config) (mode string, blocked error) {
	if interceptByDefault && runningAsService() && !interceptModeDefault {
		return "", errInterceptDefaultLegacyService
	}
	return platformDefaultInterceptMode(cfg)
}

// interceptModeFromArgs returns the --intercept-mode value in a service's
// arguments, in either the "--intercept-mode value" or the
// "--intercept-mode=value" form, and whether the flag is present.
func interceptModeFromArgs(args []string) (mode string, ok bool) {
	for i, arg := range args {
		switch {
		case arg == "--intercept-mode":
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", true
		case strings.HasPrefix(arg, "--intercept-mode="):
			return strings.TrimPrefix(arg, "--intercept-mode="), true
		}
	}
	return "", false
}

// interceptDefaultFromArgs reports whether a service's arguments carry the
// --intercept-mode-default marker, as "--intercept-mode-default" or
// "--intercept-mode-default=<bool>".
func interceptDefaultFromArgs(args []string) bool {
	for _, arg := range args {
		switch {
		case arg == interceptModeDefaultFlag:
			return true
		case strings.HasPrefix(arg, interceptModeDefaultFlag+"="):
			on, err := strconv.ParseBool(strings.TrimPrefix(arg, interceptModeDefaultFlag+"="))
			return err == nil && on
		}
	}
	return false
}

// installInterceptMode decides what "ctrld start" records in the arguments of
// the service it installs when the command line selects no mode: an explicit
// mode, the --intercept-mode-default marker (markDefault), or nothing.
//
// Recording is what lets an installed service tell a fresh install from one
// that predates the dns default (defaultInterceptMode):
//
//   - a fresh install: the marker. The service applies the platform default
//     itself, below service.intercept_mode and against the config it fetches,
//     so a mode or an os upstream in a Control D custom config still counts.
//   - a reinstall over an existing service: keep what its arguments record,
//     a mode or the marker. If they record neither, it was installed before the
//     default and ran in Standard mode, so record "off". existingArgs is nil
//     when they could not be read; that also records "off", so a read failure
//     cannot switch a Standard install to intercept mode. A reinstall whose
//     config sets service.intercept_mode records nothing: the config decides.
//
// Platforms without the dns default record nothing, as before.
func installInterceptMode(flag string, cfg *ctrld.Config, installed bool, existingArgs []string) (mode string, markDefault bool) {
	if flag != "" || !interceptByDefault {
		return "", false
	}
	if !installed {
		return "", true
	}
	if mode, ok := interceptModeFromArgs(existingArgs); ok && validInterceptMode(mode) {
		return mode, false
	}
	if interceptDefaultFromArgs(existingArgs) {
		return "", true
	}
	if cfg != nil && cfg.Service.InterceptMode != "" {
		return "", false
	}
	return "off", false
}

// resolveInterceptMode applies the intercept mode precedence: an explicit
// --intercept-mode value, then service.intercept_mode, then the platform
// default for cfg. "off" at either explicit level is a selection like "dns" or
// "hard", and stops the lookup: it selects interface DNS mode even where the
// default is "dns".
func resolveInterceptMode(flag string, cfg *ctrld.Config) (mode, source string) {
	configured := ""
	if cfg != nil {
		configured = cfg.Service.InterceptMode
	}
	switch {
	case flag != "":
		return flag, interceptModeSourceFlag
	case configured != "":
		return configured, interceptModeSourceConfig
	}
	mode, _ = defaultInterceptMode(cfg)
	return mode, interceptModeSourceDefault
}
