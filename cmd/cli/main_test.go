package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/Control-D-Inc/ctrld"
)

var logOutput strings.Builder

func TestMain(m *testing.M) {
	l := zerolog.New(&logOutput)
	mainLog.Store(&ctrld.Logger{Logger: &l})
	os.Exit(m.Run())
}
