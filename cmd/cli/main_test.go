package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

var logOutput strings.Builder

func TestMain(m *testing.M) {
	l := zerolog.New(&logOutput)
	mainLog.Store(&l)
	os.Exit(m.Run())
}
