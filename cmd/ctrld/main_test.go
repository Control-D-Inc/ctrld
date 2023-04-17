package main

import (
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

var logOutput strings.Builder

func TestMain(m *testing.M) {
	mainLog = zerolog.New(&logOutput)
	os.Exit(m.Run())
}
