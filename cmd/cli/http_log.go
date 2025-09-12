package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

// HTTP log server endpoint constants
const (
	httpLogEndpointPing = "/ping"
	httpLogEndpointLogs = "/logs"
	httpLogEndpointExit = "/exit"
)

// httpLogClient sends logs to an HTTP server via POST requests.
// This replaces the logConn functionality with HTTP-based communication.
type httpLogClient struct {
	baseURL string
	client  *http.Client
}

// newHTTPLogClient creates a new HTTP log client
func newHTTPLogClient(sockPath string) *httpLogClient {
	return &httpLogClient{
		baseURL: "http://unix",
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", sockPath)
				},
			},
		},
	}
}

// Write sends log data to the HTTP server via POST request
func (hlc *httpLogClient) Write(b []byte) (int, error) {
	// Send log data via HTTP POST to /logs endpoint
	resp, err := hlc.client.Post(hlc.baseURL+httpLogEndpointLogs, "text/plain", bytes.NewReader(b))
	if err != nil {
		// Ignore errors to prevent log pollution, just like the original logConn
		return len(b), nil
	}
	resp.Body.Close()
	return len(b), nil
}

// Ping tests if the HTTP log server is available
func (hlc *httpLogClient) Ping() error {
	resp, err := hlc.client.Get(hlc.baseURL + httpLogEndpointPing)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Close sends exit signal to the HTTP server
func (hlc *httpLogClient) Close() error {
	// Send exit signal via HTTP POST with empty body
	resp, err := hlc.client.Post(hlc.baseURL+httpLogEndpointExit, "text/plain", bytes.NewReader([]byte{}))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// GetLogs retrieves all collected logs from the HTTP server
func (hlc *httpLogClient) GetLogs() ([]byte, error) {
	resp, err := hlc.client.Get(hlc.baseURL + httpLogEndpointLogs)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return []byte{}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// httpLogServer starts an HTTP server listening on unix socket to collect logs from runCmd.
func httpLogServer(sockPath string, stopLogCh chan struct{}) error {
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return fmt.Errorf("invalid log sock path: %w", err)
	}

	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("could not listen log socket: %w", err)
	}
	defer ln.Close()

	// Create a log writer to store all logs
	logWriter := newLogWriter()

	// Use a sync.Once to ensure channel is only closed once
	var channelClosed sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc(httpLogEndpointPing, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc(httpLogEndpointLogs, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			// POST /logs - Store log data
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Failed to read request body", http.StatusBadRequest)
				return
			}

			// Store log data in log writer
			logWriter.Write(body)

			w.WriteHeader(http.StatusOK)

		case http.MethodGet:
			// GET /logs - Retrieve all logs
			// Get all logs from the log writer
			logWriter.mu.Lock()
			logs := logWriter.buf.Bytes()
			logWriter.mu.Unlock()

			if len(logs) == 0 {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write(logs)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc(httpLogEndpointExit, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Close the stop channel to signal completion (only once)
		channelClosed.Do(func() {
			close(stopLogCh)
		})
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{Handler: mux}
	return server.Serve(ln)
}
