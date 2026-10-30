package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/nettest"
)

func unixDomainSocketPath(t *testing.T) string {
	t.Helper()
	sockPath, err := nettest.LocalPath()
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	return sockPath
}

func TestHTTPLogServer(t *testing.T) {
	sockPath := unixDomainSocketPath(t)

	// Create log channel
	stopLogCh := make(chan struct{})

	// Start HTTP log server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- httpLogServer(sockPath, stopLogCh)
	}()

	// Wait a bit for server to start
	time.Sleep(100 * time.Millisecond)

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
	}

	t.Run("Ping endpoint", func(t *testing.T) {
		resp, err := client.Get("http://unix" + httpLogEndpointPing)
		if err != nil {
			t.Fatalf("Failed to ping server: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("Ping endpoint wrong method", func(t *testing.T) {
		resp, err := client.Post("http://unix"+httpLogEndpointPing, "text/plain", bytes.NewReader([]byte("test")))
		if err != nil {
			t.Fatalf("Failed to send POST to ping: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", resp.StatusCode)
		}
	})

	t.Run("Log endpoint", func(t *testing.T) {
		testLog := "test log message"
		resp, err := client.Post("http://unix"+httpLogEndpointLogs, "text/plain", bytes.NewReader([]byte(testLog)))
		if err != nil {
			t.Fatalf("Failed to send log: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		// Check if log was stored by retrieving it
		logsResp, err := client.Get("http://unix" + httpLogEndpointLogs)
		if err != nil {
			t.Fatalf("Failed to get logs: %v", err)
		}
		defer logsResp.Body.Close()

		if logsResp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for logs, got %d", logsResp.StatusCode)
		}

		body, err := io.ReadAll(logsResp.Body)
		if err != nil {
			t.Fatalf("Failed to read logs: %v", err)
		}

		if !strings.Contains(string(body), testLog) {
			t.Errorf("Expected log '%s' not found in stored logs", testLog)
		}
	})

	t.Run("Log endpoint wrong method", func(t *testing.T) {
		// Test unsupported method (PUT) on /logs endpoint
		req, err := http.NewRequest("PUT", "http://unix"+httpLogEndpointLogs, bytes.NewReader([]byte("test")))
		if err != nil {
			t.Fatalf("Failed to create PUT request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send PUT to logs: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", resp.StatusCode)
		}
	})

	t.Run("Exit endpoint", func(t *testing.T) {
		resp, err := client.Post("http://unix"+httpLogEndpointExit, "text/plain", bytes.NewReader([]byte{}))
		if err != nil {
			t.Fatalf("Failed to send exit: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		// Check if channel is closed by trying to read from it
		select {
		case _, ok := <-stopLogCh:
			if ok {
				t.Error("Expected channel to be closed, but it's still open")
			}
		case <-time.After(1 * time.Second):
			t.Error("Timeout waiting for channel closure")
		}
	})

	t.Run("Exit endpoint wrong method", func(t *testing.T) {
		resp, err := client.Get("http://unix" + httpLogEndpointExit)
		if err != nil {
			t.Fatalf("Failed to send GET to exit: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", resp.StatusCode)
		}
	})

	t.Run("Multiple log messages", func(t *testing.T) {
		logs := []string{"log1", "log2", "log3"}

		for _, log := range logs {
			resp, err := client.Post("http://unix"+httpLogEndpointLogs, "text/plain", bytes.NewReader([]byte(log+"\n")))
			if err != nil {
				t.Fatalf("Failed to send log '%s': %v", log, err)
			}
			resp.Body.Close()
		}

		// Check if all logs were stored by retrieving them
		logsResp, err := client.Get("http://unix" + httpLogEndpointLogs)
		if err != nil {
			t.Fatalf("Failed to get logs: %v", err)
		}
		defer logsResp.Body.Close()

		if logsResp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for logs, got %d", logsResp.StatusCode)
		}

		body, err := io.ReadAll(logsResp.Body)
		if err != nil {
			t.Fatalf("Failed to read logs: %v", err)
		}

		logContent := string(body)
		for i, expectedLog := range logs {
			if !strings.Contains(logContent, expectedLog) {
				t.Errorf("Log %d: expected '%s' not found in stored logs", i, expectedLog)
			}
		}
	})

	t.Run("Large log message", func(t *testing.T) {
		largeLog := strings.Repeat("a", 1024*10) // 10KB log message
		resp, err := client.Post("http://unix"+httpLogEndpointLogs, "text/plain", bytes.NewReader([]byte(largeLog)))
		if err != nil {
			t.Fatalf("Failed to send large log: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		// Check if large log was stored by retrieving it
		logsResp, err := client.Get("http://unix" + httpLogEndpointLogs)
		if err != nil {
			t.Fatalf("Failed to get logs: %v", err)
		}
		defer logsResp.Body.Close()

		if logsResp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for logs, got %d", logsResp.StatusCode)
		}

		body, err := io.ReadAll(logsResp.Body)
		if err != nil {
			t.Fatalf("Failed to read logs: %v", err)
		}

		if !strings.Contains(string(body), largeLog) {
			t.Error("Large log message was not stored correctly")
		}
	})

	// Clean up
	os.Remove(sockPath)
}

func TestHTTPLogServerInvalidSocketPath(t *testing.T) {
	// Test with invalid socket path
	invalidPath := "/invalid/path/that/does/not/exist.sock"
	stopLogCh := make(chan struct{})

	err := httpLogServer(invalidPath, stopLogCh)
	if err == nil {
		t.Error("Expected error for invalid socket path")
	}

	if !strings.Contains(err.Error(), "could not listen log socket") {
		t.Errorf("Expected 'could not listen log socket' error, got: %v", err)
	}
}

func TestHTTPLogServerSocketInUse(t *testing.T) {
	// Create a temporary socket path
	sockPath := unixDomainSocketPath(t)
	defer os.Remove(sockPath)

	// Create the first server
	stopLogCh1 := make(chan struct{})
	serverErr1 := make(chan error, 1)
	go func() {
		serverErr1 <- httpLogServer(sockPath, stopLogCh1)
	}()

	// Wait for first server to start
	time.Sleep(100 * time.Millisecond)

	// Try to create a second server on the same socket
	stopLogCh2 := make(chan struct{})
	err := httpLogServer(sockPath, stopLogCh2)
	if err == nil {
		t.Error("Expected error when socket is already in use")
	}

	if !strings.Contains(err.Error(), "could not listen log socket") {
		t.Errorf("Expected 'could not listen log socket' error, got: %v", err)
	}
}

func TestHTTPLogServerConcurrentRequests(t *testing.T) {
	// Create a temporary socket path
	sockPath := unixDomainSocketPath(t)
	defer os.Remove(sockPath)

	// Create log channel
	stopLogCh := make(chan struct{})

	// Start HTTP log server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- httpLogServer(sockPath, stopLogCh)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
	}

	// Send concurrent requests
	numRequests := 10
	done := make(chan bool, numRequests)

	for i := 0; i < numRequests; i++ {
		go func(i int) {
			defer func() { done <- true }()

			logMsg := fmt.Sprintf("concurrent log %d", i)
			resp, err := client.Post("http://unix"+httpLogEndpointLogs, "text/plain", bytes.NewReader([]byte(logMsg)))
			if err != nil {
				t.Errorf("Failed to send concurrent log %d: %v", i, err)
				return
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200 for request %d, got %d", i, resp.StatusCode)
			}
		}(i)
	}

	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		select {
		case <-done:
			// Request completed
		case <-time.After(5 * time.Second):
			t.Errorf("Timeout waiting for concurrent request %d", i)
		}
	}

	// Check if all logs were stored by retrieving them
	logsResp, err := client.Get("http://unix" + httpLogEndpointLogs)
	if err != nil {
		t.Fatalf("Failed to get logs: %v", err)
	}
	defer logsResp.Body.Close()

	if logsResp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for logs, got %d", logsResp.StatusCode)
	}

	body, err := io.ReadAll(logsResp.Body)
	if err != nil {
		t.Fatalf("Failed to read logs: %v", err)
	}

	logContent := string(body)
	// Verify all logs were stored
	for i := 0; i < numRequests; i++ {
		expectedLog := fmt.Sprintf("concurrent log %d", i)
		if !strings.Contains(logContent, expectedLog) {
			t.Errorf("Log '%s' was not stored", expectedLog)
		}
	}
}

func TestHTTPLogServerErrorHandling(t *testing.T) {
	// Create a temporary socket path
	sockPath := unixDomainSocketPath(t)
	defer os.Remove(sockPath)

	// Create log channel
	stopLogCh := make(chan struct{})

	// Start HTTP log server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- httpLogServer(sockPath, stopLogCh)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
	}

	t.Run("Invalid request body", func(t *testing.T) {
		// Test with malformed request - this will fail at HTTP level, not server level
		// The server will return 400 Bad Request for invalid body
		resp, err := client.Post("http://unix"+httpLogEndpointLogs, "text/plain", strings.NewReader(""))
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		// Empty body should still be processed successfully
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})
}

func BenchmarkHTTPLogServer(b *testing.B) {
	// Create a temporary socket path
	tmpDir := b.TempDir()
	sockPath := filepath.Join(tmpDir, "bench.sock")

	// Create log channel
	stopLogCh := make(chan struct{})

	// Start HTTP log server in a goroutine
	go func() {
		httpLogServer(sockPath, stopLogCh)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
	}

	// Benchmark log sending
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logMsg := fmt.Sprintf("benchmark log %d", i)
		resp, err := client.Post("http://unix"+httpLogEndpointLogs, "text/plain", bytes.NewReader([]byte(logMsg)))
		if err != nil {
			b.Fatalf("Failed to send log: %v", err)
		}
		resp.Body.Close()
	}

	// Clean up
	os.Remove(sockPath)
}

func TestHTTPLogClient(t *testing.T) {
	// Create a temporary socket path
	sockPath := unixDomainSocketPath(t)
	defer os.Remove(sockPath)

	// Create log channel
	stopLogCh := make(chan struct{})

	// Start HTTP log server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- httpLogServer(sockPath, stopLogCh)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Create HTTP log client
	client := newHTTPLogClient(sockPath)

	t.Run("Ping server", func(t *testing.T) {
		err := client.Ping()
		if err != nil {
			t.Errorf("Ping failed: %v", err)
		}
	})

	t.Run("Write logs", func(t *testing.T) {
		testLog := "test log message from client"
		n, err := client.Write([]byte(testLog))
		if err != nil {
			t.Errorf("Write failed: %v", err)
		}
		if n != len(testLog) {
			t.Errorf("Expected to write %d bytes, wrote %d", len(testLog), n)
		}

		// Check if log was stored by retrieving it
		logs, err := client.GetLogs()
		if err != nil {
			t.Fatalf("Failed to get logs: %v", err)
		}

		if !strings.Contains(string(logs), testLog) {
			t.Errorf("Expected log '%s' not found in stored logs", testLog)
		}
	})

	t.Run("Close client", func(t *testing.T) {
		err := client.Close()
		if err != nil {
			t.Errorf("Close failed: %v", err)
		}

		// Check if channel is closed (signaling completion)
		select {
		case _, ok := <-stopLogCh:
			if ok {
				t.Error("Expected channel to be closed, but it's still open")
			}
		case <-time.After(1 * time.Second):
			t.Error("Timeout waiting for channel closure")
		}
	})
}

func TestHTTPLogClientServerUnavailable(t *testing.T) {
	// Create client with non-existent socket
	sockPath := "/non/existent/socket.sock"
	client := newHTTPLogClient(sockPath)

	t.Run("Ping unavailable server", func(t *testing.T) {
		err := client.Ping()
		if err == nil {
			t.Error("Expected ping to fail for unavailable server")
		}
	})

	t.Run("Write to unavailable server", func(t *testing.T) {
		testLog := "test log message"
		n, err := client.Write([]byte(testLog))
		if err != nil {
			t.Errorf("Write should not return error (ignores errors): %v", err)
		}
		if n != len(testLog) {
			t.Errorf("Expected to write %d bytes, wrote %d", len(testLog), n)
		}
	})

	t.Run("Close unavailable server", func(t *testing.T) {
		err := client.Close()
		if err == nil {
			t.Error("Expected close to fail for unavailable server")
		}
	})
}

func BenchmarkHTTPLogClient(b *testing.B) {
	// Create a temporary socket path
	tmpDir := b.TempDir()
	sockPath := filepath.Join(tmpDir, "bench.sock")

	// Create log channel
	stopLogCh := make(chan struct{})

	// Start HTTP log server in a goroutine
	go func() {
		httpLogServer(sockPath, stopLogCh)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Create HTTP log client
	client := newHTTPLogClient(sockPath)

	// Benchmark client writes
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logMsg := fmt.Sprintf("benchmark write %d", i)
		client.Write([]byte(logMsg))
	}

	// Clean up
	os.Remove(sockPath)
}

func TestHTTPLogServerWithLogWriter(t *testing.T) {
	// Create a temporary socket path
	sockPath := unixDomainSocketPath(t)
	defer os.Remove(sockPath)

	// Create log channel
	stopLogCh := make(chan struct{})

	// Start HTTP log server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- httpLogServer(sockPath, stopLogCh)
	}()

	// Wait a bit for server to start
	time.Sleep(100 * time.Millisecond)

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
	}

	t.Run("Store and retrieve logs", func(t *testing.T) {
		// Send multiple log messages
		logs := []string{"log message 1", "log message 2", "log message 3"}

		for _, log := range logs {
			resp, err := client.Post("http://unix"+httpLogEndpointLogs, "text/plain", bytes.NewReader([]byte(log+"\n")))
			if err != nil {
				t.Fatalf("Failed to send log '%s': %v", log, err)
			}
			resp.Body.Close()
		}

		// Retrieve all logs
		resp, err := client.Get("http://unix" + httpLogEndpointLogs)
		if err != nil {
			t.Fatalf("Failed to get logs: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read logs response: %v", err)
		}

		logContent := string(body)
		for _, log := range logs {
			if !strings.Contains(logContent, log) {
				t.Errorf("Expected log '%s' not found in retrieved logs", log)
			}
		}
	})

	t.Run("Empty logs endpoint", func(t *testing.T) {
		// Create a new server for this test
		sockPath2 := unixDomainSocketPath(t)
		stopLogCh2 := make(chan struct{})

		go func() {
			httpLogServer(sockPath2, stopLogCh2)
		}()
		time.Sleep(100 * time.Millisecond)

		client2 := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", sockPath2)
				},
			},
		}

		resp, err := client2.Get("http://unix" + httpLogEndpointLogs)
		if err != nil {
			t.Fatalf("Failed to get logs: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("Expected status 204, got %d", resp.StatusCode)
		}

		os.Remove(sockPath2)
	})

	t.Run("Channel closure on exit", func(t *testing.T) {
		// Send exit signal
		resp, err := client.Post("http://unix"+httpLogEndpointExit, "text/plain", bytes.NewReader([]byte{}))
		if err != nil {
			t.Fatalf("Failed to send exit: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		// Check if channel is closed by trying to read from it
		select {
		case _, ok := <-stopLogCh:
			if ok {
				t.Error("Expected channel to be closed, but it's still open")
			}
		case <-time.After(1 * time.Second):
			t.Error("Timeout waiting for channel closure")
		}
	})
}

func TestHTTPLogClientGetLogs(t *testing.T) {
	// Create a temporary socket path
	sockPath := unixDomainSocketPath(t)
	defer os.Remove(sockPath)

	// Create log channel
	stopLogCh := make(chan struct{})

	// Start HTTP log server in a goroutine
	go func() {
		httpLogServer(sockPath, stopLogCh)
	}()

	// Wait a bit for server to start
	time.Sleep(100 * time.Millisecond)

	// Create HTTP log client
	client := newHTTPLogClient(sockPath)

	t.Run("Get logs from client", func(t *testing.T) {
		// Send some logs
		testLogs := []string{"client log 1", "client log 2", "client log 3"}
		for _, log := range testLogs {
			client.Write([]byte(log + "\n"))
		}

		// Retrieve logs using client method
		logs, err := client.GetLogs()
		if err != nil {
			t.Fatalf("Failed to get logs: %v", err)
		}

		logContent := string(logs)
		for _, log := range testLogs {
			if !strings.Contains(logContent, log) {
				t.Errorf("Expected log '%s' not found in retrieved logs", log)
			}
		}
	})

	t.Run("Get empty logs", func(t *testing.T) {
		// Create a new client for empty logs test
		sockPath2 := unixDomainSocketPath(t)
		stopLogCh2 := make(chan struct{})

		go func() {
			httpLogServer(sockPath2, stopLogCh2)
		}()
		time.Sleep(100 * time.Millisecond)

		client2 := newHTTPLogClient(sockPath2)
		logs, err := client2.GetLogs()
		if err != nil {
			t.Fatalf("Failed to get empty logs: %v", err)
		}

		if len(logs) != 0 {
			t.Errorf("Expected empty logs, got %d bytes", len(logs))
		}

		os.Remove(sockPath2)
	})
}
