//go:build !freebsd

package router

import (
	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld"
)

const osName = ""

func newOsRouter(cfg *ctrld.Config, cdMode bool) Router {
	return &osRouter{}
}

type osRouter struct{}

func (d *osRouter) ConfigureService(_ *service.Config) error {
	return nil
}

func (d *osRouter) Install(_ *service.Config) error {
	return nil
}

func (d *osRouter) Uninstall(_ *service.Config) error {
	return nil
}

func (d *osRouter) PreRun() error {
	return nil
}

func (d *osRouter) Setup() error {
	return nil
}

func (d *osRouter) Cleanup() error {
	return nil
}
