package router

import (
	"bytes"
	"strings"
	"testing"
)

func Test_merlinParsePostConf(t *testing.T) {
	origContent := "# foo"
	data := strings.Join([]string{
		merlinDNSMasqPostConfTmpl,
		"\n",
		merlinDNSMasqPostConfMarker,
		"\n",
	}, "\n")

	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{"empty", "", ""},
		{"no ctrld", origContent, origContent},
		{"ctrld with data", data + origContent, origContent},
		{"ctrld without data", data, ""},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			//t.Parallel()
			if got := merlinParsePostConf([]byte(tc.data)); !bytes.Equal(got, []byte(tc.expected)) {
				t.Errorf("unexpected result, want: %q, got: %q", tc.expected, string(got))
			}
		})
	}
}
