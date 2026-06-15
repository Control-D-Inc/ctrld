package cli

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

var logOutput strings.Builder

func TestMain(m *testing.M) {
	l := zerolog.New(&logOutput)
	mainLog.Store(&l)

	// Stub the self-upgrade command builder for the whole test binary. The real
	// builder execs os.Executable() — which under `go test` IS this test binary
	// — with positional args ("upgrade", ...). `go test` stops flag parsing at
	// the first positional arg and ignores the rest, so the child just re-runs
	// the entire suite, hits the upgrade tests again, and spawns more children:
	// a fork bomb of detached processes that stalls the host and (on Windows)
	// holds the test binary's image locked, breaking CI artifact cleanup.
	// Point it at the test binary with a no-match -test.run so any test that
	// reaches performUpgrade still exercises the cmd.Start() success path while
	// the child exits immediately without recursing.
	newUpgradeCmd = func(exe string) *exec.Cmd {
		return exec.Command(exe, "-test.run=^$")
	}

	os.Exit(m.Run())
}
