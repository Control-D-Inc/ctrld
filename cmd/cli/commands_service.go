package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

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

// ServiceCommand handles service-related operations
type ServiceCommand struct {
	serviceManager *ServiceManager
}

// initializeServiceManager creates a service manager with default configuration
func (sc *ServiceCommand) initializeServiceManager() (service.Service, *prog, error) {
	svcConfig := sc.createServiceConfig()
	return sc.initializeServiceManagerWithServiceConfig(svcConfig)
}

// initializeServiceManagerWithServiceConfig creates a service manager with the given configuration
func (sc *ServiceCommand) initializeServiceManagerWithServiceConfig(svcConfig *service.Config) (service.Service, *prog, error) {
	p := &prog{}

	s, err := newService(p, svcConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create service: %w", err)
	}

	sc.serviceManager = &ServiceManager{prog: p, svc: s}
	return s, p, nil
}

// NewServiceCommand creates a new service command handler
func NewServiceCommand() *ServiceCommand {
	return &ServiceCommand{}
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

// InitServiceCmd creates the service command with proper logic and aliases
func InitServiceCmd() *cobra.Command {
	// Create service command handlers
	sc := NewServiceCommand()

	startCmd, startCmdAlias := createStartCommands(sc)
	rootCmd.AddCommand(startCmdAlias)

	// Stop command
	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the ctrld service",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: sc.Stop,
	}
	stopCmd.Flags().StringVarP(&iface, "iface", "", "", `Reset DNS setting for iface, "auto" means the default interface gateway`)
	stopCmd.Flags().Int64VarP(&deactivationPin, "pin", "", defaultDeactivationPin, `Pin code for stopping ctrld`)
	_ = stopCmd.Flags().MarkHidden("pin")

	// Restart command
	restartCmd := &cobra.Command{
		Use:   "restart",
		Short: "Restart the ctrld service",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: sc.Restart,
	}

	// Status command
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show status of the ctrld service",
		Args:  cobra.NoArgs,
		RunE:  sc.Status,
	}
	if runtime.GOOS == "darwin" {
		// On darwin, running status command without privileges may return wrong information.
		statusCmd.PreRun = func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		}
	}

	// Reload command
	reloadCmd := &cobra.Command{
		Use:   "reload",
		Short: "Reload the ctrld service",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: sc.Reload,
	}

	// Uninstall command
	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and uninstall the ctrld service",
		Long: `Stop and uninstall the ctrld service.

NOTE: Uninstalling will set DNS to values provided by DHCP.`,
		Args: cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: sc.Uninstall,
	}

	// Interfaces command - use the existing InitInterfacesCmd function
	interfacesCmd := InitInterfacesCmd()

	stopCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "stop",
		Short: "Quick stop service and remove DNS from interface",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("iface") {
				os.Args = append(os.Args, "--iface="+ifaceStartStop)
			}
			iface = ifaceStartStop
			return stopCmd.RunE(cmd, args)
		},
	}
	stopCmdAlias.Flags().StringVarP(&ifaceStartStop, "iface", "", "auto", `Reset DNS setting for iface, "auto" means the default interface gateway`)
	stopCmdAlias.Flags().AddFlagSet(stopCmd.Flags())
	rootCmd.AddCommand(stopCmdAlias)

	// Create aliases for other service commands
	restartCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "restart",
		Short: "Restart the ctrld service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return restartCmd.RunE(cmd, args)
		},
	}
	rootCmd.AddCommand(restartCmdAlias)

	reloadCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "reload",
		Short: "Reload the ctrld service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return reloadCmd.RunE(cmd, args)
		},
	}
	rootCmd.AddCommand(reloadCmdAlias)

	statusCmdAlias := &cobra.Command{
		Use:   "status",
		Short: "Show status of the ctrld service",
		Args:  cobra.NoArgs,
		RunE:  statusCmd.RunE,
	}
	rootCmd.AddCommand(statusCmdAlias)

	uninstallCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "uninstall",
		Short: "Stop and uninstall the ctrld service",
		Long: `Stop and uninstall the ctrld service.

NOTE: Uninstalling will set DNS to values provided by DHCP.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("iface") {
				os.Args = append(os.Args, "--iface="+ifaceStartStop)
			}
			iface = ifaceStartStop
			return uninstallCmd.RunE(cmd, args)
		},
	}
	uninstallCmdAlias.Flags().StringVarP(&ifaceStartStop, "iface", "", "auto", `Reset DNS setting for iface, "auto" means the default interface gateway`)
	uninstallCmdAlias.Flags().AddFlagSet(uninstallCmd.Flags())
	rootCmd.AddCommand(uninstallCmdAlias)

	// Create service command
	serviceCmd := &cobra.Command{
		Use:   "service",
		Short: "Manage ctrld service",
		Args:  cobra.OnlyValidArgs,
	}
	serviceCmd.ValidArgs = make([]string, 7)
	serviceCmd.ValidArgs[0] = startCmd.Use
	serviceCmd.ValidArgs[1] = stopCmd.Use
	serviceCmd.ValidArgs[2] = restartCmd.Use
	serviceCmd.ValidArgs[3] = reloadCmd.Use
	serviceCmd.ValidArgs[4] = statusCmd.Use
	serviceCmd.ValidArgs[5] = uninstallCmd.Use
	serviceCmd.ValidArgs[6] = interfacesCmd.Use

	serviceCmd.AddCommand(uninstallCmd)
	serviceCmd.AddCommand(startCmd)
	serviceCmd.AddCommand(stopCmd)
	serviceCmd.AddCommand(restartCmd)
	serviceCmd.AddCommand(reloadCmd)
	serviceCmd.AddCommand(statusCmd)
	serviceCmd.AddCommand(interfacesCmd)

	rootCmd.AddCommand(serviceCmd)

	return serviceCmd
}
