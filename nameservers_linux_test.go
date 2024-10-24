package ctrld

import (
	"testing"
)

func Test_virtualInterfaces(t *testing.T) {
	vis := virtualInterfaces()
	t.Log(vis)
}
