package cli

import (
	"fmt"
	"time"

	"github.com/kardianos/service"
)

// dialSocketControlServerTimeout is the default timeout to wait when ping control server.
const dialSocketControlServerTimeout = 30 * time.Second

// ServiceManager handles service operations
type ServiceManager struct {
	prog *prog
	svc  service.Service
}

// NewServiceManager creates a new service manager
func NewServiceManager() (*ServiceManager, error) {
	p := &prog{}

	// Create a proper service configuration
	svcConfig := &service.Config{
		Name:        ctrldServiceName,
		DisplayName: "Control-D Helper Service",
		Description: "A highly configurable, multi-protocol DNS forwarding proxy",
		Option:      service.KeyValue{},
	}

	s, err := newService(p, svcConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create service: %w", err)
	}
	return &ServiceManager{prog: p, svc: s}, nil
}

// Status returns the current service status
func (sm *ServiceManager) Status() (service.Status, error) {
	return sm.svc.Status()
}
