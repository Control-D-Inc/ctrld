package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/docker/go-units"
	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

// LogCommand handles log-related operations
type LogCommand struct {
	serviceManager *ServiceManager
	controlClient  *controlClient
}

// NewLogCommand creates a new log command handler
func NewLogCommand() (*LogCommand, error) {
	sm, err := NewServiceManager()
	if err != nil {
		return nil, err
	}

	dir, err := socketDir()
	if err != nil {
		return nil, fmt.Errorf("failed to find ctrld home dir: %w", err)
	}

	cc := newControlClient(filepath.Join(dir, ctrldControlUnixSock))
	return &LogCommand{
		serviceManager: sm,
		controlClient:  cc,
	}, nil
}

// warnRuntimeLoggingNotEnabled logs a warning about runtime logging not being enabled
func (lc *LogCommand) warnRuntimeLoggingNotEnabled() {
	mainLog.Load().Warn().Msg("runtime debug logging is not enabled")
	mainLog.Load().Warn().Msg(`ctrld may be running without "--cd" flag or logging is already enabled`)
}

// SendLogs sends runtime debug logs to ControlD
func (lc *LogCommand) SendLogs(cmd *cobra.Command, args []string) error {
	status, err := lc.serviceManager.Status()
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
	status, err := lc.serviceManager.Status()
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
	}

	var logs logViewResponse
	if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
		return fmt.Errorf("failed to decode view logs result: %w", err)
	}

	if logs.Data == "" {
		mainLog.Load().Notice().Msg("No runtime logs available")
		return nil
	}

	fmt.Print(logs.Data)
	return nil
}
