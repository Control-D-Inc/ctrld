package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	"github.com/docker/go-units"
	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

// LogCommand handles log-related operations
type LogCommand struct {
	controlClient *controlClient
}

// NewLogCommand creates a new log command handler
func NewLogCommand() (*LogCommand, error) {
	dir, err := socketDir()
	if err != nil {
		return nil, fmt.Errorf("failed to find ctrld home dir: %w", err)
	}

	cc := newControlClient(filepath.Join(dir, ctrldControlUnixSock))
	return &LogCommand{
		controlClient: cc,
	}, nil
}

// warnRuntimeLoggingNotEnabled logs a warning about runtime logging not being enabled
func (lc *LogCommand) warnRuntimeLoggingNotEnabled() {
	mainLog.Load().Warn().Msg("runtime debug logging is not enabled")
	mainLog.Load().Warn().Msg(`ctrld may be running without "--cd" flag or logging is already enabled`)
}

// SendLogs sends runtime debug logs to ControlD
func (lc *LogCommand) SendLogs(cmd *cobra.Command, args []string) error {
	sc := NewServiceCommand()
	s, _, err := sc.initializeServiceManager()
	if err != nil {
		return err
	}

	status, err := s.Status()
	if errors.Is(err, service.ErrNotInstalled) {
		mainLog.Load().Warn().Msg("service not installed")
		return nil
	}
	if status == service.StatusStopped {
		mainLog.Load().Warn().Msg("service is not running")
		return nil
	}

	resp, err := lc.controlClient.post(sendLogsPath, nil)
	if err != nil {
		return fmt.Errorf("failed to send logs: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusServiceUnavailable:
		mainLog.Load().Warn().Msg("runtime logs could only be sent once per minute")
		return nil
	case http.StatusMovedPermanently:
		lc.warnRuntimeLoggingNotEnabled()
		return nil
	}

	var logs logSentResponse
	if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
		return fmt.Errorf("failed to decode sent logs result: %w", err)
	}

	if logs.Error != "" {
		return fmt.Errorf("failed to send logs: %s", logs.Error)
	}

	mainLog.Load().Notice().Msgf("Sent %s of runtime logs", units.BytesSize(float64(logs.Size)))
	return nil
}

// ViewLogs views current runtime debug logs
func (lc *LogCommand) ViewLogs(cmd *cobra.Command, args []string) error {
	sc := NewServiceCommand()
	s, _, err := sc.initializeServiceManager()
	if err != nil {
		return err
	}

	status, err := s.Status()
	if errors.Is(err, service.ErrNotInstalled) {
		mainLog.Load().Warn().Msg("service not installed")
		return nil
	}
	if status == service.StatusStopped {
		mainLog.Load().Warn().Msg("service is not running")
		return nil
	}

	resp, err := lc.controlClient.post(viewLogsPath, nil)
	if err != nil {
		return fmt.Errorf("failed to get logs: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusMovedPermanently:
		lc.warnRuntimeLoggingNotEnabled()
		return nil
	case http.StatusBadRequest:
		mainLog.Load().Warn().Msg("runtime debugs log is not available")
		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			mainLog.Load().Fatal().Err(err).Msg("failed to read response body")
		}
		mainLog.Load().Warn().Msgf("ctrld process response:\n\n%s\n", string(buf))
		return nil
	case http.StatusOK:
	}

	var logs logViewResponse
	if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
		return fmt.Errorf("failed to decode view logs result: %w", err)
	}

	fmt.Print(logs.Data)
	return nil
}

// InitLogCmd creates the log command with proper logic
func InitLogCmd(rootCmd *cobra.Command) *cobra.Command {
	lc, err := NewLogCommand()
	if err != nil {
		panic(fmt.Sprintf("failed to create log command: %v", err))
	}

	logSendCmd := &cobra.Command{
		Use:   "send",
		Short: "Send runtime debug logs to ControlD",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: lc.SendLogs,
	}

	logViewCmd := &cobra.Command{
		Use:   "view",
		Short: "View current runtime debug logs",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: lc.ViewLogs,
	}

	logCmd := &cobra.Command{
		Use:   "log",
		Short: "Manage runtime debug logs",
		Args:  cobra.OnlyValidArgs,
		ValidArgs: []string{
			logSendCmd.Use,
			logViewCmd.Use,
		},
	}
	logCmd.AddCommand(logSendCmd)
	logCmd.AddCommand(logViewCmd)
	rootCmd.AddCommand(logCmd)

	return logCmd
}
