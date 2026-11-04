package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"

	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// diag reports the facts that support asks for on every provisioning
// ticket. A customer or admin can then paste the output of one command
// instead of a hunt through logs and preference panes. It runs without
// root. A section that needs data the current user cannot read reports
// that, instead of a failure of the whole command. On an installed device
// those are the provisioning-result and the service-state sections, because
// the service wrote the file as root and the service manager answers only
// root.
const diagCmdLong = `Collect diagnostics for a provisioning failure.

Reports the client version, MDM-managed preferences (macOS only), the last
provisioning result, service state, and whether the Control D API is
reachable. Safe to paste into a support ticket: it never prints the
provisioning token itself, only whether one is present.

Run it with root or administrator rights on an installed device to include
the last provisioning result and the service state. Without those rights,
the two sections report permission denied.`

// diagAPIProbeTimeout bounds the API reachability check. diag must return
// promptly even when the network is unreachable.
const diagAPIProbeTimeout = 5 * time.Second

// diagOverallTimeout bounds the whole report. No single probe, however
// wedged, may keep "ctrld diag" from returning.
const diagOverallTimeout = 15 * time.Second

// diagServiceStateTimeout bounds one service-state probe. systemctl or
// launchctl can hang against a wedged service manager; the kardianos
// service package gives us no way to cancel that call, so we race it
// against this timer in a goroutine instead.
const diagServiceStateTimeout = 5 * time.Second

// diagFieldMaxLen bounds any single field pulled from outside ctrld's own
// control (a managed-preferences value), so a misconfigured profile cannot
// blow up the report's size.
const diagFieldMaxLen = 256

// managedPrefsDomain is the MDM-managed preferences domain ctrld reads its
// provisioning settings from.
const managedPrefsDomain = "/Library/Managed Preferences/com.controld.ctrld"

// managedPrefsBin is invoked with an absolute path so diag never depends on
// PATH.
const managedPrefsBin = "/usr/bin/defaults"

// managedPrefsSupported reports whether this platform has managed
// preferences to read. A var so tests can exercise the macOS-shaped report
// on any OS.
var managedPrefsSupported = func() bool { return runtime.GOOS == "darwin" }

// managedPrefsRead runs `defaults read <domain> [key]` and returns the
// trimmed value, or ok=false if the domain or key does not exist. A var so
// tests seam it instead of shelling out for real. It honors the caller's
// ctx so a near-expired overall deadline cuts this short too.
var managedPrefsRead = func(ctx context.Context, domain, key string) (string, bool) {
	args := []string{"read", domain}
	if key != "" {
		args = append(args, key)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(probeCtx, managedPrefsBin, args...).Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// diagProbeReachability makes the one HTTPS probe api_reachability reports
// on. A var so tests replace it instead of hitting the network.
var diagProbeReachability = controld.ProbeReachability

type diagReport struct {
	ClientVersion      string                 `json:"client_version"`
	Commit             string                 `json:"commit"`
	ManagedPreferences diagManagedPreferences `json:"managed_preferences"`
	ProvisionResult    diagProvisionResult    `json:"provision_result"`
	ServiceState       diagServiceState       `json:"service_state"`
	APIReachability    diagAPIReachability    `json:"api_reachability"`
}

type diagManagedPreferences struct {
	Applicable     bool   `json:"applicable"`
	ProfilePresent bool   `json:"profile_present"`
	ProvisionToken string `json:"provision_token"` // "present" or "absent"; never the value
	CustomHostname string `json:"custom_hostname"`
	InterceptMode  string `json:"intercept_mode"`
	Note           string `json:"note"`
}

// diagProvisionResult mirrors the on-disk provision_result.json for report
// purposes. AgeSeconds is -1 when no age applies (nothing recorded, or the
// timestamp did not parse). Message and Attempts are re-bounded on read: the
// file was written bounded, but diag must not trust that a file on disk
// still is (a mismatched version, or hand-edited).
type diagProvisionResult struct {
	Status     string                 `json:"status"` // none, recorded, untrusted, unreadable, corrupt
	Stage      string                 `json:"stage"`
	Code       string                 `json:"code"`
	ExitCode   int                    `json:"exit_code"`
	Message    string                 `json:"message"`
	Attempts   []provisionBindAttempt `json:"attempts,omitempty"`
	AgeSeconds int64                  `json:"age_seconds"`
}

type diagServiceState struct {
	Status string `json:"status"` // running, stopped, not_installed, unknown
	Note   string `json:"note"`
}

type diagAPIReachability struct {
	Reachable  bool   `json:"reachable"`
	ErrorClass string `json:"error_class"` // empty when reachable
}

// diagProvisionResultPath locates the result file where the service wrote
// it, with the same homedir override the writer obeys. The user home-dir
// resolver has a fallback to the home directory of the current user when
// /etc/controld is not writable, and every run without root hits that
// fallback. A diag that used it would report "none recorded" for a file it
// never opened. A var so tests can point it at a temp dir.
var diagProvisionResultPath = func() string {
	if homedir != "" {
		return filepath.Join(homedir, provisionResultFileName)
	}
	dir, err := serviceHomeDir()
	if err != nil {
		return provisionResultPath()
	}
	return filepath.Join(dir, provisionResultFileName)
}

// diagServiceStateFn collects service_state. A var so tests can supply a
// fixed state instead of depending on whatever service happens to be
// installed on the machine running the tests.
var diagServiceStateFn = collectServiceStateReal

// buildDiagReport bounds the whole report at diagOverallTimeout: whatever
// deadline the caller passed in, a single probe wedging past this must not
// keep "ctrld diag" from returning.
func buildDiagReport(ctx context.Context) diagReport {
	ctx, cancel := context.WithTimeout(ctx, diagOverallTimeout)
	defer cancel()
	return diagReport{
		ClientVersion:      appVersion,
		Commit:             commit,
		ManagedPreferences: collectManagedPreferences(ctx),
		ProvisionResult:    collectProvisionResultDiag(),
		ServiceState:       collectServiceStateBounded(ctx),
		APIReachability:    collectAPIReachability(ctx),
	}
}

func collectManagedPreferences(ctx context.Context) diagManagedPreferences {
	if !managedPrefsSupported() {
		return diagManagedPreferences{Note: "not applicable on this platform"}
	}
	m := diagManagedPreferences{Applicable: true}
	if _, ok := managedPrefsRead(ctx, managedPrefsDomain, ""); !ok {
		m.Note = "configuration profile not found"
		return m
	}
	m.ProfilePresent = true
	// An empty value reads as absent: the postinstall refuses to provision
	// on an empty ProvisionToken, so "present" would send support the wrong
	// way.
	if v, ok := managedPrefsRead(ctx, managedPrefsDomain, "ProvisionToken"); ok && v != "" {
		m.ProvisionToken = "present"
	} else {
		m.ProvisionToken = "absent"
	}
	if v, ok := managedPrefsRead(ctx, managedPrefsDomain, "CustomHostname"); ok {
		m.CustomHostname = boundedDiagField(v)
	}
	if v, ok := managedPrefsRead(ctx, managedPrefsDomain, "InterceptMode"); ok {
		m.InterceptMode = boundedDiagField(v)
	}
	return m
}

// boundedDiagField caps a value from outside ctrld's control to a size that
// keeps the report bounded, cutting on a rune boundary so it never splits a
// multi-byte character.
func boundedDiagField(s string) string {
	if utf8.RuneCountInString(s) <= diagFieldMaxLen {
		return s
	}
	runes := []rune(s)
	return string(runes[:diagFieldMaxLen])
}

// collectProvisionResultDiag reads provision_result.json from the service
// home through the same trusted reader "ctrld start" uses, so diag never
// reports a code that contract validation would reject. A read the current
// user is not permitted to make is its own status: the file is not
// corrupt, the reader lacks root.
func collectProvisionResultDiag() diagProvisionResult {
	r, err := readProvisionResultAt(diagProvisionResultPath())
	if err != nil {
		if os.IsNotExist(err) {
			return diagProvisionResult{Status: "none", AgeSeconds: -1}
		}
		if os.IsPermission(err) {
			return diagProvisionResult{Status: "unreadable", AgeSeconds: -1}
		}
		return diagProvisionResult{Status: "corrupt", AgeSeconds: -1}
	}
	if !provisionResultTrusted(r) {
		return diagProvisionResult{Status: "untrusted", AgeSeconds: -1}
	}
	age := int64(-1)
	if ts, parseErr := time.Parse(time.RFC3339, r.Timestamp); parseErr == nil {
		if d := time.Since(ts); d >= 0 {
			age = int64(d.Round(time.Second).Seconds())
		} else {
			age = 0
		}
	}
	var attempts []provisionBindAttempt
	if r.Detail != nil {
		attempts = boundedDiagAttempts(r.Detail.Attempts)
	}
	return diagProvisionResult{
		Status:     "recorded",
		Stage:      r.Stage,
		Code:       r.Code,
		ExitCode:   r.ExitCode,
		Message:    boundedDiagField(r.Message),
		Attempts:   attempts,
		AgeSeconds: age,
	}
}

// boundedDiagAttempts re-applies the same attempt-count cap the file was
// written with, and bounds each attempt's fields, so a result file from a
// mismatched or tampered version cannot make the report unbounded.
func boundedDiagAttempts(attempts []provisionBindAttempt) []provisionBindAttempt {
	if len(attempts) > maxProvisionBindAttempts {
		attempts = attempts[:maxProvisionBindAttempts]
	}
	bounded := make([]provisionBindAttempt, len(attempts))
	for i, a := range attempts {
		bounded[i] = provisionBindAttempt{
			Addr:    boundedDiagField(a.Addr),
			Proto:   boundedDiagField(a.Proto),
			OSError: boundedDiagField(a.OSError),
		}
	}
	return bounded
}

// collectServiceStateReal is diagServiceStateFn's production implementation.
// It reuses the same service-manager wrapper "ctrld status" does, so a
// permission-limited run reports "requires elevated privileges" rather than
// a wrong status (see the launchd wrapper in service.go).
func collectServiceStateReal() diagServiceState {
	sc := NewServiceCommand()
	s, _, err := sc.initializeServiceManager()
	if err != nil {
		return diagServiceState{Status: "unknown", Note: "could not set up the service manager"}
	}
	status, statusErr := s.Status()
	switch {
	case errors.Is(statusErr, service.ErrNotInstalled):
		return diagServiceState{Status: "not_installed"}
	case statusErr != nil:
		return diagServiceState{Status: "unknown", Note: boundedDiagField(statusErr.Error())}
	case status == service.StatusRunning:
		return diagServiceState{Status: "running"}
	case status == service.StatusStopped:
		return diagServiceState{Status: "stopped"}
	default:
		return diagServiceState{Status: "unknown"}
	}
}

// collectServiceStateBounded runs diagServiceStateFn in the background and
// races it against ctx and diagServiceStateTimeout, so a wedged service
// manager reports "timed out" instead of hanging the whole diag report. The
// goroutine is left running if the probe never returns; that is harmless
// since the process exits shortly after diag prints its report.
func collectServiceStateBounded(ctx context.Context) diagServiceState {
	done := make(chan diagServiceState, 1)
	go func() { done <- diagServiceStateFn() }()

	timer := time.NewTimer(diagServiceStateTimeout)
	defer timer.Stop()

	select {
	case s := <-done:
		return s
	case <-ctx.Done():
		return diagServiceState{Status: "unknown", Note: "timed out"}
	case <-timer.C:
		return diagServiceState{Status: "unknown", Note: "timed out"}
	}
}

func collectAPIReachability(ctx context.Context) diagAPIReachability {
	probeCtx, cancel := context.WithTimeout(ctx, diagAPIProbeTimeout)
	defer cancel()
	if err := diagProbeReachability(probeCtx, cdDev); err != nil {
		return diagAPIReachability{Reachable: false, ErrorClass: classifyReachabilityError(err)}
	}
	return diagAPIReachability{Reachable: true}
}

// classifyReachabilityError turns a probe failure into a coarse class safe
// to print: no host, no address, no request details, just what kind of
// failure it was.
func classifyReachabilityError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "tls"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "connection"
	}
	return "other"
}

// diagElevateHint names the step that gets root or administrator rights on
// this OS, for the text report.
func diagElevateHint() string {
	if runtime.GOOS == "windows" {
		return "run again from an administrator prompt"
	}
	return "run again with sudo"
}

func displayOrDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// renderDiagText writes the text-mode report in a fixed section order, so
// output stays stable across runs and safe to diff or paste into a ticket.
func renderDiagText(w io.Writer, r diagReport) {
	fmt.Fprintf(w, "client version: %s (commit %s)\n\n", r.ClientVersion, r.Commit)

	fmt.Fprintln(w, "managed preferences:")
	switch {
	case !r.ManagedPreferences.Applicable:
		fmt.Fprintf(w, "  %s\n", displayOrDefault(r.ManagedPreferences.Note, "not applicable"))
	case !r.ManagedPreferences.ProfilePresent:
		fmt.Fprintf(w, "  %s\n", r.ManagedPreferences.Note)
	default:
		fmt.Fprintf(w, "  provision token: %s\n", r.ManagedPreferences.ProvisionToken)
		fmt.Fprintf(w, "  custom hostname: %s\n", displayOrDefault(r.ManagedPreferences.CustomHostname, "(not set)"))
		fmt.Fprintf(w, "  intercept mode: %s\n", displayOrDefault(r.ManagedPreferences.InterceptMode, "(not set)"))
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "last provisioning result:")
	switch r.ProvisionResult.Status {
	case "none":
		fmt.Fprintln(w, "  none recorded")
	case "untrusted":
		fmt.Fprintln(w, "  result file present but not trusted (contents ignored)")
	case "unreadable":
		fmt.Fprintf(w, "  permission denied (%s)\n", diagElevateHint())
	case "corrupt":
		fmt.Fprintln(w, "  result file present but could not be read (contents ignored)")
	default:
		fmt.Fprintf(w, "  stage: %s\n", r.ProvisionResult.Stage)
		fmt.Fprintf(w, "  code: %s\n", r.ProvisionResult.Code)
		fmt.Fprintf(w, "  exit code: %d\n", r.ProvisionResult.ExitCode)
		fmt.Fprintf(w, "  message: %s\n", r.ProvisionResult.Message)
		for _, a := range r.ProvisionResult.Attempts {
			fmt.Fprintf(w, "  attempt: %s/%s: %s\n", a.Addr, a.Proto, a.OSError)
		}
		fmt.Fprintf(w, "  age: %s\n", (time.Duration(r.ProvisionResult.AgeSeconds) * time.Second).String())
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "service state:")
	fmt.Fprintf(w, "  status: %s\n", r.ServiceState.Status)
	if r.ServiceState.Note != "" {
		fmt.Fprintf(w, "  note: %s\n", r.ServiceState.Note)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "api reachability:")
	fmt.Fprintf(w, "  reachable: %t\n", r.APIReachability.Reachable)
	if r.APIReachability.ErrorClass != "" {
		fmt.Fprintf(w, "  error class: %s\n", r.APIReachability.ErrorClass)
	}
}

func writeDiagJSON(w io.Writer, r diagReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// InitDiagCmd registers "ctrld diag" alongside the other top-level commands.
func InitDiagCmd(rootCmd *cobra.Command) *cobra.Command {
	var asJSON bool
	diagCmd := &cobra.Command{
		Use:   "diag",
		Short: "Collect diagnostics for a provisioning failure",
		Long:  diagCmdLong,
		Args:  cobra.NoArgs,
		// diag always exits 0 once it ran: a failure it finds is reported,
		// not turned into a nonzero exit. RunE returning an error would exit
		// 1 (see Main), so every branch below reports instead of erroring.
		RunE: func(cmd *cobra.Command, args []string) error {
			report := buildDiagReport(context.Background())
			if asJSON {
				if err := writeDiagJSON(cmd.OutOrStdout(), report); err != nil {
					// A closed pipe (e.g. `ctrld diag --json | head -1`) must
					// not turn into a nonzero exit; the report already ran.
					mainLog.Load().Debug().Err(err).Msg("could not write diag JSON report")
				}
				return nil
			}
			renderDiagText(cmd.OutOrStdout(), report)
			return nil
		},
	}
	diagCmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	rootCmd.AddCommand(diagCmd)
	return diagCmd
}
