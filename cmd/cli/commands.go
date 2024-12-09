package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	"github.com/spf13/cobra"
)

func initLogCmd() {
	logSendCmd := &cobra.Command{
		Use:   "send",
		Short: "Send runtime debug logs to ControlD",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			dir, err := socketDir()
			if err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to find ctrld home dir")
			}
			cc := newControlClient(filepath.Join(dir, ctrldControlUnixSock))
			resp, err := cc.post(sendLogsPath, nil)
			if err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to send logs")
			}
			defer resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusOK:
				mainLog.Load().Notice().Msg("runtime logs sent successfully")
			case http.StatusServiceUnavailable:
				mainLog.Load().Warn().Msg("runtime logs could only be sent once per minute")
			default:
				buf, err := io.ReadAll(resp.Body)
				if err != nil {
					mainLog.Load().Fatal().Err(err).Msg("failed to read response body")
				}
				mainLog.Load().Error().Msg("failed to send logs")
				mainLog.Load().Error().Msg(string(buf))
			}
		},
	}
	logViewCmd := &cobra.Command{
		Use:   "view",
		Short: "View current runtime debug logs",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			dir, err := socketDir()
			if err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to find ctrld home dir")
			}
			cc := newControlClient(filepath.Join(dir, ctrldControlUnixSock))
			resp, err := cc.post(viewLogsPath, nil)
			if err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to get logs")
			}
			defer resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusMovedPermanently:
				mainLog.Load().Warn().Msg("runtime debugs log is not enabled")
				mainLog.Load().Warn().Msg(`ctrld may be run without "--cd" flag or logging is already enabled`)
				return
			case http.StatusBadRequest:
				mainLog.Load().Warn().Msg("runtime debugs log is not available")
				return
			case http.StatusOK:
			}
			var logs logViewResponse
			if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to decode view logs result")
			}
			fmt.Println(logs.Data)
		},
	}
	logCmd := &cobra.Command{
		Use:   "log",
		Short: "Manage runtime debug logs",
		Args:  cobra.OnlyValidArgs,
		ValidArgs: []string{
			logSendCmd.Use,
		},
	}
	logCmd.AddCommand(logSendCmd)
	logCmd.AddCommand(logViewCmd)
	rootCmd.AddCommand(logCmd)
}
