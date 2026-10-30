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
	Exit(error string)
}

// Start configures utility with config.toml from provided directory.
// This function blocks until the run exits, including teardown after Stop.
// A call made while a run is active or stopping returns immediately.
// Check port availability prior to calling it.
func (c *Controller) Start(CdUID string, ProvisionID string, CustomHostname string, HomeDir string, UpstreamProto string, logLevel int, logPath string) {
	c.mu.Lock()
	if c.stopCh != nil {
		c.mu.Unlock()
		return
	}
	stopCh, doneCh := make(chan struct{}), make(chan struct{})
	c.stopCh, c.doneCh = stopCh, doneCh
	c.Config = cli.AppConfig{
		CdUID:          CdUID,
		ProvisionID:    ProvisionID,
		CustomHostname: CustomHostname,
		HomeDir:        HomeDir,
		UpstreamProto:  UpstreamProto,
		Verbose:        logLevel,
		LogPath:        logPath,
	}
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

// mapCallback maps the AppCallback interface to cli.AppCallback to avoid circular dependency
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
