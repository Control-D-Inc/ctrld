package controld

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseUID(t *testing.T) {
	tests := []struct {
		name         string
		uid          string
		wantUID      string
		wantClientID string
	}{
		{"empty", "", "", ""},
		{"only uid", "abcd1234", "abcd1234", ""},
		{"with client id", "abcd1234/clientID", "abcd1234", "clientID"},
		{"with empty clientID", "abcd1234/", "abcd1234", ""},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotUID, gotClientID := ParseRawUID(tc.uid)
			assert.Equal(t, tc.wantUID, gotUID)
			assert.Equal(t, tc.wantClientID, gotClientID)
		})
	}
}

// TestAPIErrorRecordsHTTPStatus pins the plumbing the caller's exit decision rests on.
//
// cmd/cli treats a 4xx as "this configuration is refused, restarting cannot help" and
// exits cleanly, while a 5xx keeps the abnormal exit so the service manager retries. Both
// readings need the status, and it is not in the JSON body - so a decode path that
// forgets to record it would quietly send every API error down the retry branch,
// including a deleted device that should self-uninstall and stop.
func TestAPIErrorRecordsHTTPStatus(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantCode   int
		wantMsg    string
	}{
		{
			name:       "deleted device",
			statusCode: http.StatusNotFound,
			body:       `{"error":{"message":"device does not exist","code":40402}}`,
			wantCode:   InvalidConfigCode,
			wantMsg:    "device does not exist",
		},
		{
			// A gateway error body carries no error object at all, which decodes
			// cleanly into the zero value - so the status is the only thing that
			// distinguishes it from a real rejection.
			name:       "gateway error with an empty body",
			statusCode: http.StatusBadGateway,
			body:       `{}`,
		},
		{
			name:       "service unavailable",
			statusCode: http.StatusServiceUnavailable,
			body:       `{"error":{"message":"try again later","code":0}}`,
			wantMsg:    "try again later",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := json.NewDecoder(strings.NewReader(tc.body))
			errResp, err := apiErrorFromResponse(tc.statusCode, d)
			if err != nil {
				t.Fatalf("unexpected decode error: %v", err)
			}
			if errResp.StatusCode != tc.statusCode {
				t.Errorf("StatusCode = %d, want %d: the caller cannot tell a permanent rejection from a transient failure without it", errResp.StatusCode, tc.statusCode)
			}
			if errResp.ErrorField.Code != tc.wantCode {
				t.Errorf("code = %d, want %d", errResp.ErrorField.Code, tc.wantCode)
			}
			if errResp.Error() != tc.wantMsg {
				t.Errorf("message = %q, want %q", errResp.Error(), tc.wantMsg)
			}
		})
	}

	t.Run("an undecodable body is reported as a decode failure", func(t *testing.T) {
		d := json.NewDecoder(strings.NewReader("<html>502 Bad Gateway</html>"))
		if _, err := apiErrorFromResponse(http.StatusBadGateway, d); err == nil {
			t.Error("expected a decode error for a non-JSON body")
		}
	})
}
