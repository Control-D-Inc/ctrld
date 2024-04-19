package ctrld

import (
	"runtime"
	"testing"
)

func Test_dohOsHeaderValue(t *testing.T) {
	val := dohOsHeaderValue
	if val == "" {
		t.Fatalf("empty %s", dohOsHeader)
	}
	t.Log(val)

	encodedOs := EncodeOsNameMap[runtime.GOOS]
	if encodedOs == "" {
		t.Fatalf("missing encoding value for: %q", runtime.GOOS)
	}
	decodedOs := DecodeOsNameMap[encodedOs]
	if decodedOs == "" {
		t.Fatalf("missing decoding value for: %q", runtime.GOOS)
	}
}
