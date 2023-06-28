package router

import "github.com/kardianos/service"

type dummy struct{}

func NewDummyRouter() Router {
	return &dummy{}
}

func (d *dummy) ConfigureService(_ *service.Config) error {
	return nil
}

func (d *dummy) Install(_ *service.Config) error {
	return nil
}

func (d *dummy) Uninstall(_ *service.Config) error {
	return nil
}

func (d *dummy) PreRun() error {
	return nil
}

func (d *dummy) Configure() error {
	return nil
}

func (d *dummy) Setup() error {
	return nil
}

func (d *dummy) Cleanup() error {
	return nil
}
