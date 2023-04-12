package router

import "github.com/kardianos/service"

func newSysLogger(name string, errs chan<- error) (service.Logger, error) {
	return service.ConsoleLogger, nil
}
