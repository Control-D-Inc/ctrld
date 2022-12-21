package ctrld

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_nameservers(t *testing.T) {
	ns := nameservers()
	require.NotNil(t, ns)
	t.Log(ns)
}
