package merlin

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
)

func Test_merlinParsePostConf(t *testing.T) {
	origContent := "# foo"
	data := strings.Join([]string{
		dnsmasq.MerlinPostConfTmpl,
		"\n",
		dnsmasq.MerlinPostConfMarker,
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
