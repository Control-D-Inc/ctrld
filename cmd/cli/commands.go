package cli

import (
	"fmt"
	"time"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

// dialSocketControlServerTimeout is the default timeout to wait when ping control server.
const dialSocketControlServerTimeout = 30 * time.Second

// CommandRunner interface for dependency injection and testing
type CommandRunner interface {
	RunServiceCommand(cmd *cobra.Command, args []string) error
	RunLogCommand(cmd *cobra.Command, args []string) error
	RunStatusCommand(cmd *cobra.Command, args []string) error
	RunUpgradeCommand(cmd *cobra.Command, args []string) error
	RunClientsCommand(cmd *cobra.Command, args []string) error
	RunInterfacesCommand(cmd *cobra.Command, args []string) error
}

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

// initLogCmd is now implemented in commands_log.go as InitLogCmd
// initRunCmd is now implemented in commands_run.go as InitRunCmd

// filterEmptyStrings removes empty strings from a slice
func filterEmptyStrings(slice []string) []string {
	var result []string
	for _, s := range slice {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}
