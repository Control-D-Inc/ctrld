package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/kardianos/service"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"github.com/Control-D-Inc/ctrld/internal/clientinfo"
)

// ClientsCommand handles clients-related operations
type ClientsCommand struct {
	controlClient *controlClient
}

// NewClientsCommand creates a new clients command handler
func NewClientsCommand() (*ClientsCommand, error) {
	dir, err := socketDir()
	if err != nil {
		return nil, fmt.Errorf("failed to find ctrld home dir: %w", err)
	}

	cc := newControlClient(filepath.Join(dir, ctrldControlUnixSock))
	return &ClientsCommand{
		controlClient: cc,
	}, nil
}

// ListClients lists all connected clients
func (cc *ClientsCommand) ListClients(cmd *cobra.Command, args []string) error {
	// Check service status first
	sc := NewServiceCommand()
	s, _, err := sc.initializeServiceManager()
	if err != nil {
		return err
	}

	status, err := s.Status()
	if errors.Is(err, service.ErrNotInstalled) {
		mainLog.Load().Warn().Msg("Service not installed")
		return nil
	}
	if status == service.StatusStopped {
		mainLog.Load().Warn().Msg("Service is not running")
		return nil
	}

	resp, err := cc.controlClient.post(listClientsPath, nil)
	if err != nil {
		return fmt.Errorf("failed to get clients: %w", err)
	}
	defer resp.Body.Close()

	var clients []*clientinfo.Client
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return fmt.Errorf("failed to decode clients result: %w", err)
	}

	map2Slice := func(m map[string]struct{}) []string {
		s := make([]string, 0, len(m))
		for k := range m {
			if k == "" { // skip empty source from output.
				continue
			}
			s = append(s, k)
		}
		sort.Strings(s)
		return s
	}

	// If metrics is enabled, server set this for all clients, so we can check only the first one.
	// Ideally, we may have a field in response to indicate that query count should be shown, but
	// it would break earlier version of ctrld, which only look list of clients in response.
	withQueryCount := len(clients) > 0 && clients[0].IncludeQueryCount
	data := make([][]string, len(clients))
	for i, c := range clients {
		row := []string{
			c.IP.String(),
			c.Hostname,
			c.Mac,
			strings.Join(map2Slice(c.Source), ","),
		}
		if withQueryCount {
			row = append(row, strconv.FormatInt(c.QueryCount, 10))
		}
		data[i] = row
	}

	table := tablewriter.NewWriter(os.Stdout)
	headers := []string{"IP", "Hostname", "Mac", "Discovered"}
	if withQueryCount {
		headers = append(headers, "Queries")
	}
	table.SetHeader(headers)
	table.SetAutoFormatHeaders(false)
	table.AppendBulk(data)
	table.Render()

	return nil
}

// InitClientsCmd creates the clients command with proper logic
func InitClientsCmd(rootCmd *cobra.Command) *cobra.Command {
	listClientsCmd := &cobra.Command{
		Use:   "list",
		Short: "List clients that ctrld discovered",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cc, err := NewClientsCommand()
			if err != nil {
				return err
			}
			return cc.ListClients(cmd, args)
		},
	}

	clientsCmd := &cobra.Command{
		Use:   "clients",
		Short: "Manage clients",
		Args:  cobra.OnlyValidArgs,
		ValidArgs: []string{
			listClientsCmd.Use,
		},
	}
	clientsCmd.AddCommand(listClientsCmd)
	rootCmd.AddCommand(clientsCmd)

	return clientsCmd
}
