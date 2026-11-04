package cli

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"
)

// InterfacesCommand handles interfaces-related operations
type InterfacesCommand struct{}

// NewInterfacesCommand creates a new interfaces command handler
func NewInterfacesCommand() (*InterfacesCommand, error) {
	return &InterfacesCommand{}, nil
}

// ListInterfaces lists all network interfaces
func (ic *InterfacesCommand) ListInterfaces(cmd *cobra.Command, args []string) error {
	withEachPhysicalInterfaces("", "Interface list", func(i *net.Interface) error {
		fmt.Printf("Index : %d\n", i.Index)
		fmt.Printf("Name  : %s\n", i.Name)
		var status string
		if i.Flags&net.FlagUp != 0 {
			status = "Up"
		} else {
			status = "Down"
		}
		fmt.Printf("Status: %s\n", status)
		addrs, _ := i.Addrs()
		for i, ipaddr := range addrs {
			if i == 0 {
				fmt.Printf("Addrs : %v\n", ipaddr)
				continue
			}
			fmt.Printf("        %v\n", ipaddr)
		}
		nss, err := currentStaticDNS(i)
		if err != nil {
			mainLog.Load().Warn().Err(err).Msg("Failed to get DNS")
		}
		if len(nss) == 0 {
			nss = currentDNS(i)
		}
		for i, dns := range nss {
			if i == 0 {
				fmt.Printf("DNS   : %s\n", dns)
				continue
			}
			fmt.Printf("      : %s\n", dns)
		}
		println()
		return nil
	})
	return nil
}

// InitInterfacesCmd creates the interfaces command with proper logic
func InitInterfacesCmd(_ *cobra.Command) *cobra.Command {
	listInterfacesCmd := &cobra.Command{
		Use:   "list",
		Short: "List network interfaces",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ic, err := NewInterfacesCommand()
			if err != nil {
				return err
			}
			return ic.ListInterfaces(cmd, args)
		},
	}

	interfacesCmd := &cobra.Command{
		Use:   "interfaces",
		Short: "Manage network interfaces",
		Args:  cobra.OnlyValidArgs,
		ValidArgs: []string{
			listInterfacesCmd.Use,
		},
	}
	interfacesCmd.AddCommand(listInterfacesCmd)

	return interfacesCmd
}
