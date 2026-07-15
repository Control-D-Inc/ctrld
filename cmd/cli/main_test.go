package cli

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/Control-D-Inc/ctrld"
)

var logOutput strings.Builder

func TestMain(m *testing.M) {
	// Create a custom writer that writes to logOutput
	writer := zapcore.AddSync(&logOutput)

	// Create zap encoder
	encoderConfig := zap.NewDevelopmentEncoderConfig()
	encoder := zapcore.NewConsoleEncoder(encoderConfig)

	// Create core that writes to our string builder
	core := zapcore.NewCore(encoder, writer, zap.DebugLevel)

	// Create logger
	l := zap.New(core)

	mainLog.Store(&ctrld.Logger{Logger: l})

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
