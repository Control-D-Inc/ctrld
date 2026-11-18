package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/Control-D-Inc/ctrld"
)

// logOutput is the log sink for the whole test binary. Tests share it with any
// background goroutine the code under test starts (watchdogs, timers), so it
// must tolerate concurrent writes.
var logOutput syncBuffer

// syncBuffer is a strings.Builder guarded by a mutex.
type syncBuffer struct {
	mu sync.Mutex
	sb strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}

// envFakeVersionOutput makes this test binary impersonate a ctrld executable: when
// set, the process writes the value to stdout and exits without running any test, so
// binaryVersion() can be exercised on every platform without building or shipping a
// fixture binary. The value envFakeVersionSilent produces no output at all, which
// reproduces the unusable ctrld.exe_previous seen in the Firewall Mode incident.
//
// This must be handled before m.Run(), which is what parses the test flags: the child
// is invoked as "<binary> --version" and would otherwise die on an unknown flag.
const (
	envFakeVersionOutput = "CTRLD_TEST_FAKE_VERSION_OUTPUT"
	envFakeVersionSilent = "<silent>"
)

func TestMain(m *testing.M) {
	if out := os.Getenv(envFakeVersionOutput); out != "" {
		if out != envFakeVersionSilent {
			fmt.Println(out)
		}
		os.Exit(0)
	}

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
