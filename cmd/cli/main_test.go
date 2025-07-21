package cli

import (
	"os"
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
	os.Exit(m.Run())
}
