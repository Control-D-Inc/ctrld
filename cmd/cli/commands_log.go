package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

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

// logRequestPath adds the query that makes the control server read every log
// file, not only the newest debug bytes.
func logRequestPath(path string, full bool) string {
	if !full {
		return path
	}
	return path + "?full=1"
}

// warnRuntimeLoggingNotEnabled logs a warning about runtime logging not being enabled
func (lc *LogCommand) warnRuntimeLoggingNotEnabled() {
	mainLog.Load().Warn().Msg("Runtime debug logging is not enabled")
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
		mainLog.Load().Warn().Msg("Service not installed")
		return nil
	}
	if status == service.StatusStopped {
		mainLog.Load().Warn().Msg("Service is not running")
		return nil
	}

	full, _ := cmd.Flags().GetBool("full")
	resp, err := lc.controlClient.post(logRequestPath(sendLogsPath, full), nil)
	if err != nil {
		return fmt.Errorf("failed to send logs: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusServiceUnavailable:
		mainLog.Load().Warn().Msg("Runtime logs could only be sent once per minute")
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
		mainLog.Load().Warn().Msg("Service not installed")
		return nil
	}
	if status == service.StatusStopped {
		mainLog.Load().Warn().Msg("Service is not running")
		return nil
	}

	full, _ := cmd.Flags().GetBool("full")
	resp, err := lc.controlClient.post(logRequestPath(viewLogsPath, full), nil)
	if err != nil {
		return fmt.Errorf("failed to get logs: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusMovedPermanently:
		lc.warnRuntimeLoggingNotEnabled()
		return nil
	case http.StatusBadRequest:
		mainLog.Load().Warn().Msg("Runtime debug logs are not available")
		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			mainLog.Load().Fatal().Err(err).Msg("Failed to read response body")
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

// TailLogs streams live runtime debug logs to the terminal
func (lc *LogCommand) TailLogs(cmd *cobra.Command, args []string) error {
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

	tailLines, _ := cmd.Flags().GetInt("lines")
	tailPath := fmt.Sprintf("%s?lines=%d", tailLogsPath, tailLines)
	resp, err := lc.controlClient.postStream(tailPath, nil)
	if err != nil {
		return fmt.Errorf("failed to connect for log tailing: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusMovedPermanently:
		lc.warnRuntimeLoggingNotEnabled()
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("unexpected response status: %d", resp.StatusCode)
	}

	// Set up signal handling for clean shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Stream output to stdout.
		buf := make([]byte, 4096)
		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				os.Stdout.Write(buf[:n])
			}
			if readErr != nil {
				if readErr != io.EOF {
					mainLog.Load().Error().Err(readErr).Msg("Error reading log stream")
				}
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			msg := fmt.Sprintf("\nexiting: %s\n", context.Cause(ctx).Error())
			os.Stdout.WriteString(msg)
		}
	case <-done:
	}

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
		Long:  "Send runtime debug logs to ControlD. On macOS, an administrator can enable service.allow_unprivileged_log_send and restart ctrld to allow standard users to send bounded diagnostics. --full still requires elevation.",
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if delegatedLogSendCLI() {
				if full, _ := cmd.Flags().GetBool("full"); full {
					return errors.New("log send --full requires administrator privileges")
				}
				return nil
			}
			checkHasElevatedPrivilege()
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// The standard-user macOS route must precede service.Status and the
			// administrative socket dial: both depend on the calling user's
			// launchd context. socketDir already ran when InitLogCmd built the
			// command; for a standard user it falls back to the home directory
			// without error, so it is harmless here.
			if delegatedLogSendCLI() {
				full, _ := cmd.Flags().GetBool("full")
				return runDelegatedLogSend(cmd.Context(), full)
			}
			return lc.SendLogs(cmd, args)
		},
	}
	logSendCmd.Flags().Bool("full", false, "Send every log file, not only the newest 10 MB of debug")

	logViewCmd := &cobra.Command{
		Use:   "view",
		Short: "View current runtime debug logs",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: lc.ViewLogs,
	}
	logViewCmd.Flags().Bool("full", false, "Show every log file, not only the newest 10 MB of debug")

	logTailCmd := &cobra.Command{
		Use:   "tail",
		Short: "Tail live runtime debug logs",
		Long:  "Stream live runtime debug logs to the terminal, similar to tail -f. Press Ctrl+C to stop.",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: lc.TailLogs,
	}
	logTailCmd.Flags().IntP("lines", "n", 10, "Number of historical lines to show on connect")

	logCmd := &cobra.Command{
		Use:   "log",
		Short: "Manage runtime debug logs",
		Args:  cobra.OnlyValidArgs,
		ValidArgs: []string{
			logSendCmd.Use,
			logViewCmd.Use,
			logTailCmd.Use,
		},
	}
	logCmd.AddCommand(logSendCmd)
	logCmd.AddCommand(logViewCmd)
	logCmd.AddCommand(logTailCmd)
	rootCmd.AddCommand(logCmd)

	return logCmd
}
