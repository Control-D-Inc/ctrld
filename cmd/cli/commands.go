package cli

import (
	"fmt"
	"time"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"

	"github.com/Control-D-Inc/ctrld"
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

func initRunCmd() *cobra.Command {
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run the DNS proxy server",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			RunCobraCommand(cmd)
		},
	}
	runCmd.Flags().BoolVarP(&daemon, "daemon", "d", false, "Run as daemon")
	runCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to config file")
	runCmd.Flags().StringVarP(&configBase64, "base64_config", "", "", "Base64 encoded config")
	runCmd.Flags().StringVarP(&listenAddress, "listen", "", "", "Listener address and port, in format: address:port")
	runCmd.Flags().StringVarP(&primaryUpstream, "primary_upstream", "", "", "Primary upstream endpoint")
	runCmd.Flags().StringVarP(&secondaryUpstream, "secondary_upstream", "", "", "Secondary upstream endpoint")
	runCmd.Flags().StringSliceVarP(&domains, "domains", "", nil, "List of domain to apply in a split DNS policy")
	runCmd.Flags().StringVarP(&logPath, "log", "", "", "Path to log file")
	runCmd.Flags().IntVarP(&cacheSize, "cache_size", "", 0, "Enable cache with size items")
	runCmd.Flags().StringVarP(&cdUID, cdUidFlagName, "", "", "Control D resolver uid")
	runCmd.Flags().StringVarP(&cdOrg, cdOrgFlagName, "", "", "Control D provision token")
	runCmd.Flags().StringVarP(&customHostname, customHostnameFlagName, "", "", "Custom hostname passed to ControlD API")
	runCmd.Flags().BoolVarP(&cdDev, "dev", "", false, "Use Control D dev resolver/domain")
	_ = runCmd.Flags().MarkHidden("dev")
	runCmd.Flags().StringVarP(&homedir, "homedir", "", "", "")
	_ = runCmd.Flags().MarkHidden("homedir")
	runCmd.Flags().StringVarP(&iface, "iface", "", "", `Update DNS setting for iface, "auto" means the default interface gateway`)
	_ = runCmd.Flags().MarkHidden("iface")
	runCmd.Flags().StringVarP(&cdUpstreamProto, "proto", "", ctrld.ResolverTypeDOH, `Control D upstream type, either "doh" or "doh3"`)

	runCmd.FParseErrWhitelist = cobra.FParseErrWhitelist{UnknownFlags: true}
	rootCmd.AddCommand(runCmd)

	return runCmd
}

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
