package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

// ServiceCommand handles service-related operations
type ServiceCommand struct {
	serviceManager *ServiceManager
}

// NewServiceCommand creates a new service command handler
func NewServiceCommand() (*ServiceCommand, error) {
	sm, err := NewServiceManager()
	if err != nil {
		return nil, err
	}

	return &ServiceCommand{
		serviceManager: sm,
	}, nil
}

// createServiceConfig creates a properly initialized service configuration
func (sc *ServiceCommand) createServiceConfig() *service.Config {
	return &service.Config{
		Name:        ctrldServiceName,
		DisplayName: "Control-D Helper Service",
		Description: "A highly configurable, multi-protocol DNS forwarding proxy",
		Option:      service.KeyValue{},
	}
}

// Install installs the service
func (sc *ServiceCommand) Install(cmd *cobra.Command, args []string) error {
	svcConfig := sc.createServiceConfig()

	// Set the working directory to the executable's directory
	if exe, err := os.Executable(); err == nil {
		svcConfig.WorkingDirectory = filepath.Dir(exe)
	}

	if err := sc.serviceManager.svc.Install(); err != nil {
		return fmt.Errorf("failed to install service: %w", err)
	}

	mainLog.Load().Notice().Msg("Service installed successfully")
	return nil
}

// Uninstall uninstalls the service
func (sc *ServiceCommand) Uninstall(cmd *cobra.Command, args []string) error {
	if err := sc.serviceManager.svc.Uninstall(); err != nil {
		return fmt.Errorf("failed to uninstall service: %w", err)
	}

	mainLog.Load().Notice().Msg("Service uninstalled successfully")
	return nil
}

// Start starts the service
func (sc *ServiceCommand) Start(cmd *cobra.Command, args []string) error {
	if err := sc.serviceManager.svc.Start(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	mainLog.Load().Notice().Msg("Service started successfully")
	return nil
}

// Stop stops the service
func (sc *ServiceCommand) Stop(cmd *cobra.Command, args []string) error {
	if err := sc.serviceManager.svc.Stop(); err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	mainLog.Load().Notice().Msg("Service stopped successfully")
	return nil
}

// Status returns the service status
func (sc *ServiceCommand) Status(cmd *cobra.Command, args []string) error {
	status, err := sc.serviceManager.Status()
	if err != nil {
		if err == service.ErrNotInstalled {
			mainLog.Load().Warn().Msg("Service not installed")
			return nil
		}
		return fmt.Errorf("failed to get service status: %w", err)
	}

	switch status {
	case service.StatusRunning:
		mainLog.Load().Notice().Msg("Service is running")
	case service.StatusStopped:
		mainLog.Load().Warn().Msg("Service is stopped")
	default:
		mainLog.Load().Warn().Msgf("Service status: %v", status)
	}

	return nil
}
