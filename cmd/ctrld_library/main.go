package ctrld_library

import (
	"time"

	"github.com/Control-D-Inc/ctrld/cmd/cli"
)

// stopTimeout bounds how long Stop waits for ctrld to release its resources.
const stopTimeout = 15 * time.Second

// Controller holds global state
type Controller struct {
	stopCh      chan struct{}
	doneCh      chan struct{}
	AppCallback AppCallback
	Config      cli.AppConfig
}

// NewController provides reference to global state to be managed by android vpn service and iOS network extension.
// reference is not safe for concurrent use.
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
// This function will block until Stop is called
// Check port availability prior to calling it.
func (c *Controller) Start(CdUID string, ProvisionID string, CustomHostname string, HomeDir string, UpstreamProto string, logLevel int, logPath string) {
	if c.stopCh == nil {
		c.stopCh = make(chan struct{})
		c.doneCh = make(chan struct{})
		defer close(c.doneCh)
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
		cli.RunMobile(&c.Config, &appCallback, c.stopCh)
	}
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

func (c *Controller) Stop(restart bool, pin int64) int {
	var errorCode = 0
	// Force disconnect without checking pin.
	// In iOS restart is required if vpn detects no connectivity after network change.
	if !restart {
		errorCode = cli.CheckDeactivationPin(pin, c.stopCh)
	}
	if errorCode == 0 && c.stopCh != nil {
		close(c.stopCh)
		c.stopCh = nil
		if c.doneCh != nil {
			select {
			case <-c.doneCh:
			case <-time.After(stopTimeout):
			}
			c.doneCh = nil
		}
	}
	return errorCode
}

func (c *Controller) IsRunning() bool {
	return c.stopCh != nil
}
