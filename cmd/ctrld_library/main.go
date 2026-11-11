package ctrld_library

import (
	"sync"
	"time"

	"github.com/Control-D-Inc/ctrld/cmd/cli"
)

// stopTimeout bounds how long Stop waits for ctrld to release its resources.
const stopTimeout = 15 * time.Second

var (
	runMobile            = cli.RunMobile
	checkDeactivationPin = cli.CheckDeactivationPin
	setNameservers       = cli.SetMobileNameservers
)

// Controller holds global state. Start, Stop and IsRunning are safe for
// concurrent use. AppCallback and Config must not be accessed concurrently.
type Controller struct {
	mu          sync.Mutex
	pinMu       sync.Mutex // Serializes PIN checks, which use CLI global state.
	stopCh      chan struct{}
	doneCh      chan struct{}
	AppCallback AppCallback
	Config      cli.AppConfig
}

// NewController provides reference to global state to be managed by android vpn service and iOS network extension.
func NewController(appCallback AppCallback) *Controller {
	return &Controller{AppCallback: appCallback}
}

// AppCallback provides access to app instance.
type AppCallback interface {
	Hostname() string
	LanIp() string
	MacAddress() string
	// Exit gets a failure line of the run. ctrld calls it on the thread that
	// called Start or on a Go thread, always before the run ends. The run
	// does not end until Exit returns. So Exit must return without waiting
	// for the run to end: it must not call Stop, wait for Start to return,
	// or wait for a thread that can be in Stop. Otherwise Stop waits its
	// full 15 seconds and returns while the run is still active.
	//
	// If Exit gives the line to another thread, it must also give the run
	// that the line belongs to, because the next run can start before that
	// thread reads the line.
	Exit(error string)
}

// LogLevelNotice is the StartOptions.LogLevel that writes only notice, warn,
// and error lines.
const LogLevelNotice = -1

// StartOptions configures StartWithOptions. gomobile exports only fields of
// basic types.
type StartOptions struct {
	CdUID          string
	CustomHostname string
	HomeDir        string
	UpstreamProto  string
	// LogLevel is the level of the ctrld log, the same value as the -v flag of
	// the CLI. It applies as follows when LogPath is empty:
	//
	//   - LogLevelNotice (-1): ctrld.log in HomeDir gets notice, warn, and
	//     error lines.
	//   - 0: ctrld.log gets debug lines.
	//   - 1: ctrld.log gets info lines. Each DNS query writes its query name.
	//   - 2: ctrld.log gets debug lines.
	//
	// When LogPath is set, a LogLevel of 0 or less writes debug lines to it.
	// With LogLevelNotice, a log_level in the custom configuration of the
	// resolver can change the level.
	//
	// Thus LogLevelNotice with an empty LogPath keeps query names out of
	// ctrld.log. On mobile, ctrld also removes the resolver UID, the provision
	// token, and the paths of URLs from the lines that it writes to its log
	// files.
	LogLevel int
	LogPath  string
	// Dev makes ctrld use the dev API, like the --dev flag of the CLI.
	Dev bool
	// MemoryLimitMiB, if more than 0, sets the Go memory limit of the process
	// before the run starts. 0 keeps the current limit.
	MemoryLimitMiB int
	// Nameservers is a comma-separated list of the OS resolvers of the device.
	// On iOS, ctrld cannot read them, so the app supplies them. ctrld uses them
	// for the "os" upstream and for the exclude rules. SetNameservers changes
	// them during the run. Each start replaces the list that an earlier
	// SetNameservers set, so pass the current list here at every start.
	Nameservers string
}

// NewStartOptions returns options with LogLevel set to LogLevelNotice.
func NewStartOptions() *StartOptions {
	return &StartOptions{LogLevel: LogLevelNotice}
}

// Start configures utility with config.toml from provided directory.
// This function blocks until the run exits, including teardown after Stop.
// A call made while a run is active or stopping returns immediately.
// Check port availability prior to calling it.
// In Control D mode the listener address is fixed. When another process
// holds it, Exit gets a stage=listener line with the code
// LISTENER_CONFIGURED_ADDR_UNAVAILABLE.
func (c *Controller) Start(CdUID string, ProvisionID string, CustomHostname string, HomeDir string, UpstreamProto string, logLevel int, logPath string) {
	c.start(cli.AppConfig{
		CdUID:          CdUID,
		ProvisionID:    ProvisionID,
		CustomHostname: CustomHostname,
		HomeDir:        HomeDir,
		UpstreamProto:  UpstreamProto,
		Verbose:        logLevel,
		LogPath:        logPath,
	})
}

// StartWithOptions is Start with the configuration in o. It blocks and
// ignores a call during a run, as Start does. A nil o is NewStartOptions().
// It provisions by resolver UID only: StartOptions has no provision token.
func (c *Controller) StartWithOptions(o *StartOptions) {
	if o == nil {
		o = NewStartOptions()
	}
	c.start(cli.AppConfig{
		CdUID:          o.CdUID,
		CustomHostname: o.CustomHostname,
		HomeDir:        o.HomeDir,
		UpstreamProto:  o.UpstreamProto,
		Verbose:        o.LogLevel,
		LogPath:        o.LogPath,
		Dev:            o.Dev,
		MemoryLimitMiB: o.MemoryLimitMiB,
		Nameservers:    o.Nameservers,
	})
}

// SetNameservers replaces the OS resolvers with the comma-separated list csv.
// Call it when the network of the device changes. It is safe to call from
// any thread, also during a run. A csv with no IP address keeps the current
// OS resolvers. The next StartWithOptions replaces the list with
// StartOptions.Nameservers.
func (c *Controller) SetNameservers(csv string) {
	setNameservers(csv)
}

func (c *Controller) start(config cli.AppConfig) {
	c.mu.Lock()
	if c.stopCh != nil {
		c.mu.Unlock()
		return
	}
	stopCh, doneCh := make(chan struct{}), make(chan struct{})
	c.stopCh, c.doneCh = stopCh, doneCh
	c.Config = config
	appCallback := mapCallback(c.AppCallback)
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		// Only the completed run releases the guard, even if Stop timed out.
		close(doneCh)
		c.stopCh, c.doneCh = nil, nil
	}()
	runMobile(&c.Config, &appCallback, stopCh)
}

// As workaround to avoid circular dependency between cli and ctrld_library module
func mapCallback(callback AppCallback) cli.AppCallback {
	return cli.AppCallback{
		HostName: func() string {
			return callback.Hostname()
		},
		LanIp: func() string {
			return callback.LanIp()
		},
		MacAddress: func() string {
			return callback.MacAddress()
		},
		Exit: func(err string) {
			callback.Exit(err)
		},
	}
}

// Stop requests shutdown after validating pin, unless restart bypasses the check.
// A zero result means the stop request was accepted, not that teardown finished.
// After cancellation it waits up to 15 seconds. Callers must check IsRunning
// after Stop: while it remains true, teardown still owns the session and Start
// will be rejected. PIN failure codes are returned unchanged.
func (c *Controller) Stop(restart bool, pin int64) int {
	// Keep this request bound to its original run while PIN validation blocks.
	c.mu.Lock()
	stopCh, doneCh := c.stopCh, c.doneCh
	c.mu.Unlock()

	// Force disconnect without checking pin.
	// In iOS restart is required if vpn detects no connectivity after network change.
	if !restart {
		c.pinMu.Lock()
		errorCode := checkDeactivationPin(pin, stopCh)
		c.pinMu.Unlock()
		if errorCode != 0 {
			return errorCode
		}
	}
	if stopCh != nil {
		c.mu.Lock()
		select {
		case <-stopCh:
		default:
			close(stopCh)
		}
		c.mu.Unlock()

		timer := time.NewTimer(stopTimeout)
		defer timer.Stop()
		select {
		case <-doneCh:
		case <-timer.C:
		}
	}
	return 0
}

// IsRunning remains true until the run has finished releasing its resources.
func (c *Controller) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopCh != nil
}
