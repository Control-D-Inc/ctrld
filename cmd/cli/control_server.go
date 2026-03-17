package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/kardianos/service"
	dto "github.com/prometheus/client_model/go"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

const (
	contentTypeJson  = "application/json"
	listClientsPath  = "/clients"
	startedPath      = "/started"
	reloadPath       = "/reload"
	deactivationPath = "/deactivation"
	cdPath           = "/cd"
	ifacePath        = "/iface"
	viewLogsPath     = "/log/view"
	sendLogsPath     = "/log/send"
	tailLogsPath     = "/log/tail"
)

type ifaceResponse struct {
	Name          string `json:"name"`
	All           bool   `json:"all"`
	OK            bool   `json:"ok"`
	InterceptMode string `json:"intercept_mode,omitempty"` // "dns", "hard", or "" (not intercepting)
}

// controlServer represents an HTTP server for handling control requests
type controlServer struct {
	server *http.Server
	mux    *http.ServeMux
	addr   string
}

// newControlServer creates a new control server instance
func newControlServer(addr string) (*controlServer, error) {
	mux := http.NewServeMux()
	s := &controlServer{
		server: &http.Server{Handler: mux},
		mux:    mux,
	}
	s.addr = addr
	return s, nil
}

func (s *controlServer) start() error {
	_ = os.Remove(s.addr)
	unixListener, err := net.Listen("unix", s.addr)
	if l, ok := unixListener.(*net.UnixListener); ok {
		l.SetUnlinkOnClose(true)
	}
	if err != nil {
		return err
	}
	go s.server.Serve(unixListener)
	return nil
}

func (s *controlServer) stop() error {
	_ = os.Remove(s.addr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *controlServer) register(pattern string, handler http.Handler) {
	s.mux.Handle(pattern, jsonResponse(handler))
}

func (p *prog) registerControlServerHandler() {
	p.cs.register(listClientsPath, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		p.Debug().Msg("Handling list clients request")

		clients := p.ciTable.ListClients()
		p.Debug().Int("client_count", len(clients)).Msg("Retrieved clients list")

		sort.Slice(clients, func(i, j int) bool {
			return clients[i].IP.Less(clients[j].IP)
		})
		p.Debug().Msg("Sorted clients by IP address")

		if p.metricsQueryStats.Load() {
			p.Debug().Msg("Metrics query stats enabled, collecting query counts")

			for idx, client := range clients {
				p.Debug().
					Int("index", idx).
					Str("ip", client.IP.String()).
					Str("mac", client.Mac).
					Str("hostname", client.Hostname).
					Msg("Processing client metrics")

				client.IncludeQueryCount = true
				dm := &dto.Metric{}

				if statsClientQueriesCount.MetricVec == nil {
					p.Debug().
						Str("client_ip", client.IP.String()).
						Msg("Skipping metrics collection: MetricVec is nil")
					continue
				}

				m, err := statsClientQueriesCount.MetricVec.GetMetricWithLabelValues(
					client.IP.String(),
					client.Mac,
					client.Hostname,
				)
				if err != nil {
					p.Debug().
						Err(err).
						Str("client_ip", client.IP.String()).
						Str("mac", client.Mac).
						Str("hostname", client.Hostname).
						Msg("Failed to get metrics for client")
					continue
				}

				if err := m.Write(dm); err == nil && dm.Counter != nil {
					client.QueryCount = int64(dm.Counter.GetValue())
					p.Debug().
						Str("client_ip", client.IP.String()).
						Int64("query_count", client.QueryCount).
						Msg("Successfully collected query count")
				} else if err != nil {
					p.Debug().
						Err(err).
						Str("client_ip", client.IP.String()).
						Msg("Failed to write metric")
				}
			}
		} else {
			p.Debug().Msg("Metrics query stats disabled, skipping query counts")
		}

		if err := json.NewEncoder(w).Encode(&clients); err != nil {
			p.Error().
				Err(err).
				Int("client_count", len(clients)).
				Msg("Failed to encode clients response")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		p.Debug().
			Int("client_count", len(clients)).
			Msg("Successfully sent clients list response")
	}))
	p.cs.register(startedPath, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		select {
		case <-p.onStartedDone:
			w.WriteHeader(http.StatusOK)
		case <-time.After(10 * time.Second):
			w.WriteHeader(http.StatusRequestTimeout)
		}
	}))
	p.cs.register(reloadPath, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		listeners := make(map[string]*ctrld.ListenerConfig)
		p.mu.Lock()
		for k, v := range p.cfg.Listener {
			listeners[k] = &ctrld.ListenerConfig{
				IP:   v.IP,
				Port: v.Port,
			}
		}
		oldSvc := p.cfg.Service
		p.mu.Unlock()
		if err := p.sendReloadSignal(); err != nil {
			p.Error().Err(err).Msg("Could not send reload signal")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		select {
		case <-p.reloadDoneCh:
		case <-time.After(5 * time.Second):
			http.Error(w, "Timeout waiting for ctrld reload", http.StatusInternalServerError)
			return
		}

		p.mu.Lock()
		defer p.mu.Unlock()

		// Checking for cases that we could not do a reload.

		// 1. Listener config ip or port changes.
		for k, v := range p.cfg.Listener {
			l := listeners[k]
			if l == nil || l.IP != v.IP || l.Port != v.Port {
				w.WriteHeader(http.StatusCreated)
				return
			}
		}

		// 2. Service config changes.
		if !reflect.DeepEqual(oldSvc, p.cfg.Service) {
			w.WriteHeader(http.StatusCreated)
			return
		}

		// Otherwise, reload is done.
		w.WriteHeader(http.StatusOK)
	}))
	p.cs.register(deactivationPath, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		// Non-cd mode always allowing deactivation.
		if cdUID == "" {
			w.WriteHeader(http.StatusOK)
			return
		}

		loggerCtx := ctrld.LoggerCtx(context.Background(), p.logger.Load())
		// Re-fetch pin code from API.
		rcReq := &controld.ResolverConfigRequest{
			RawUID:   cdUID,
			Version:  appVersion,
			Metadata: ctrld.SystemMetadataRuntime(context.Background()),
		}
		if rc, err := controld.FetchResolverConfig(loggerCtx, rcReq, cdDev); rc != nil {
			if rc.DeactivationPin != nil {
				cdDeactivationPin.Store(*rc.DeactivationPin)
			} else {
				cdDeactivationPin.Store(defaultDeactivationPin)
			}
		} else {
			p.Warn().Err(err).Msg("Could not re-fetch deactivation pin code")
		}

		// If pin code not set, allowing deactivation.
		if !deactivationPinSet() {
			w.WriteHeader(http.StatusOK)
			return
		}

		var req deactivationRequest
		if err := json.NewDecoder(request.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusPreconditionFailed)
			p.Error().Err(err).Msg("Invalid deactivation request")
			return
		}

		code := http.StatusForbidden
		switch req.Pin {
		case cdDeactivationPin.Load():
			code = http.StatusOK
			select {
			case p.pinCodeValidCh <- struct{}{}:
			default:
			}
		case defaultDeactivationPin:
			// If the pin code was set, but users do not provide --pin, return proper code to client.
			code = http.StatusBadRequest
		}
		w.WriteHeader(code)
	}))
	p.cs.register(cdPath, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if cdUID != "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(cdUID))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	p.cs.register(ifacePath, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		res := &ifaceResponse{Name: iface}
		// p.setDNS is only called when running as a service
		if !service.Interactive() {
			<-p.csSetDnsDone
			if p.csSetDnsOk {
				res.Name = p.runningIface
				res.All = p.requiredMultiNICsConfig
				res.OK = true
				// Report intercept mode to the start command for proper log output.
				if interceptMode == "dns" || interceptMode == "hard" {
					res.InterceptMode = interceptMode
				}
			}
		}
		if err := json.NewEncoder(w).Encode(res); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			http.Error(w, fmt.Sprintf("could not marshal iface data: %v", err), http.StatusInternalServerError)
			return
		}
	}))
	p.cs.register(viewLogsPath, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		lr, err := p.logReaderRaw()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer lr.r.Close()
		if lr.size == 0 {
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
		data, err := io.ReadAll(lr.r)
		if err != nil {
			http.Error(w, fmt.Sprintf("could not read log: %v", err), http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(&logViewResponse{Data: string(data)}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			http.Error(w, fmt.Sprintf("could not marshal log data: %v", err), http.StatusInternalServerError)
			return
		}
	}))
	p.cs.register(sendLogsPath, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if time.Since(p.internalLogSent) < logWriterSentInterval {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		r, err := p.logReaderNoColor()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.size == 0 {
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
		req := &controld.LogsRequest{
			UID:  cdUID,
			Data: r.r,
		}
		p.Debug().Msg("Sending log file to ControlD server")
		resp := logSentResponse{Size: r.size}
		loggerCtx := ctrld.LoggerCtx(context.Background(), p.logger.Load())
		if err := controld.SendLogs(loggerCtx, req, cdDev); err != nil {
			p.Error().Msgf("Could not send log file to ControlD server: %v", err)
			resp.Error = err.Error()
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			p.Debug().Msg("Sending log file successfully")
			w.WriteHeader(http.StatusOK)
		}
		if err := json.NewEncoder(w).Encode(&resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		p.internalLogSent = time.Now()
	}))
	p.cs.register(tailLogsPath, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Determine logging mode and validate before starting the stream.
		var lw *logWriter
		useInternalLog := p.needInternalLogging()
		if useInternalLog {
			p.mu.Lock()
			lw = p.internalLogWriter
			p.mu.Unlock()
			if lw == nil {
				w.WriteHeader(http.StatusMovedPermanently)
				return
			}
		} else if p.cfg.Service.LogPath == "" {
			// No logging configured at all.
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}

		// Parse optional "lines" query param for initial context.
		numLines := 10
		if v := request.URL.Query().Get("lines"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				numLines = n
			}
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Transfer-Encoding", "chunked")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)

		if useInternalLog {
			// Internal logging mode: subscribe to the logWriter.

			// Send last N lines as initial context.
			if numLines > 0 {
				if tail := lw.tailLastLines(numLines); len(tail) > 0 {
					w.Write(tail)
					flusher.Flush()
				}
			}

			ch, unsub := lw.Subscribe()
			defer unsub()
			for {
				select {
				case data, ok := <-ch:
					if !ok {
						return
					}
					if _, err := w.Write(data); err != nil {
						return
					}
					flusher.Flush()
				case <-request.Context().Done():
					return
				}
			}
		} else {
			// File-based logging mode: tail the log file.
			logFile := normalizeLogFilePath(p.cfg.Service.LogPath)
			f, err := os.Open(logFile)
			if err != nil {
				// Already committed 200, just return.
				return
			}
			defer f.Close()

			// Seek to show last N lines.
			if numLines > 0 {
				if tail := tailFileLastLines(f, numLines); len(tail) > 0 {
					w.Write(tail)
					flusher.Flush()
				}
			} else {
				// Seek to end.
				f.Seek(0, io.SeekEnd)
			}

			// Poll for new data.
			buf := make([]byte, 4096)
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					n, err := f.Read(buf)
					if n > 0 {
						if _, werr := w.Write(buf[:n]); werr != nil {
							return
						}
						flusher.Flush()
					}
					if err != nil && err != io.EOF {
						return
					}
				case <-request.Context().Done():
					return
				}
			}
		}
	}))
}

// tailFileLastLines reads the last n lines from a file and returns them.
// The file position is left at the end of the file after this call.
func tailFileLastLines(f *os.File, n int) []byte {
	stat, err := f.Stat()
	if err != nil || stat.Size() == 0 {
		return nil
	}

	// Read from the end in chunks to find the last n lines.
	const chunkSize = 4096
	fileSize := stat.Size()
	var lines []byte
	offset := fileSize
	count := 0

	for offset > 0 && count <= n {
		readSize := int64(chunkSize)
		if readSize > offset {
			readSize = offset
		}
		offset -= readSize
		buf := make([]byte, readSize)
		nRead, err := f.ReadAt(buf, offset)
		if err != nil && err != io.EOF {
			break
		}
		buf = buf[:nRead]
		lines = append(buf, lines...)

		// Count newlines in this chunk.
		for _, b := range buf {
			if b == '\n' {
				count++
			}
		}
	}

	// Trim to last n lines.
	idx := 0
	nlCount := 0
	for i := len(lines) - 1; i >= 0; i-- {
		if lines[i] == '\n' {
			nlCount++
			if nlCount == n+1 {
				idx = i + 1
				break
			}
		}
	}
	lines = lines[idx:]

	// Seek to end of file for subsequent reads.
	f.Seek(0, io.SeekEnd)
	return lines
}

// jsonResponse wraps an HTTP handler to set JSON content type
func jsonResponse(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}
