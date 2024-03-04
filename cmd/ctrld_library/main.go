package ctrld_library

import (
	"github.com/Control-D-Inc/ctrld/cmd/cli"
)

// Controller holds global state
type Controller struct {
	stopCh      chan struct{}
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
func (c *Controller) Start(CdUID string, HomeDir string, UpstreamProto string, logLevel int, logPath string) {
	if c.stopCh == nil {
		c.stopCh = make(chan struct{})
		c.Config = cli.AppConfig{
			CdUID:         CdUID,
			HomeDir:       HomeDir,
			UpstreamProto: UpstreamProto,
			Verbose:       logLevel,
			LogPath:       logPath,
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

func (c *Controller) Stop(Pin int64) int {
	errorCode := cli.CheckDeactivationPin(Pin)
	if errorCode == 0 && c.stopCh != nil {
		close(c.stopCh)
		c.stopCh = nil
	}
	return errorCode
}

func (c *Controller) IsRunning() bool {
	return c.stopCh != nil
}
