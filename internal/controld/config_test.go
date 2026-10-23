package controld

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestAPIErrorDecodesRejectionReason pins the additive metadata.reason field the
// API sends on provisioning-token rejections. cmd/cli maps known reasons to their
// own failure codes, and must fall back cleanly when the field is absent or holds
// a value this build does not recognize yet.
func TestAPIErrorDecodesRejectionReason(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantReason string
	}{
		{
			name:       "known reason",
			body:       `{"error":{"message":"invalid token","code":40003,"metadata":{"reason":"token_disabled"}}}`,
			wantReason: "token_disabled",
		},
		{
			name:       "reason absent",
			body:       `{"error":{"message":"invalid token","code":40003}}`,
			wantReason: "",
		},
		{
			name:       "unknown reason value",
			body:       `{"error":{"message":"invalid token","code":40003,"metadata":{"reason":"something_new"}}}`,
			wantReason: "something_new",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := json.NewDecoder(strings.NewReader(tc.body))
			errResp, err := apiErrorFromResponse(http.StatusBadRequest, d)
			if err != nil {
				t.Fatalf("unexpected decode error: %v", err)
			}
			if errResp.ErrorField.Metadata.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", errResp.ErrorField.Metadata.Reason, tc.wantReason)
			}
		})
	}
}

// TestAPIErrorToleratesMalformedRejectionReason pins the fix for a decode error
// confined to metadata.reason: a reason sent as the wrong JSON type must not
// discard the rest of the response. Before this fix, apiErrorFromResponse
// returned the raw decode error and nothing else, which cmd/cli's
// apiFailureCode cannot recognize as an *ErrorResponse - it falls back to
// API_UNREACHABLE (a retryable bootstrap failure) instead of the permanent
// rejection the HTTP status and code actually describe.
func TestAPIErrorToleratesMalformedRejectionReason(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "reason as a number", body: `{"error":{"message":"invalid token","code":40003,"metadata":{"reason":12345}}}`},
		{name: "reason as an object", body: `{"error":{"message":"invalid token","code":40003,"metadata":{"reason":{"inner":"value"}}}}`},
		{name: "reason as null", body: `{"error":{"message":"invalid token","code":40003,"metadata":{"reason":null}}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := json.NewDecoder(strings.NewReader(tc.body))
			errResp, err := apiErrorFromResponse(http.StatusBadRequest, d)
			if err != nil {
				t.Fatalf("a malformed reason must not fail the whole decode: %v", err)
			}
			if errResp.ErrorField.Message != "invalid token" {
				t.Errorf("message = %q, want it to survive the malformed reason", errResp.ErrorField.Message)
			}
			if errResp.ErrorField.Code != 40003 {
				t.Errorf("code = %d, want it to survive the malformed reason", errResp.ErrorField.Code)
			}
			if errResp.ErrorField.Metadata.Reason != "" {
				t.Errorf("reason = %q, want empty for a malformed value", errResp.ErrorField.Metadata.Reason)
			}
		})
	}
}

// TestAPIErrorToleratesMalformedMetadata pins the same tolerance one level
// up: a metadata field that is not a JSON object must not discard the rest
// of the response. Code and Message still classify the failure, and Reason
// stays empty.
func TestAPIErrorToleratesMalformedMetadata(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "metadata as a string", body: `{"error":{"message":"invalid token","code":40003,"metadata":"foo"}}`},
		{name: "metadata as a number", body: `{"error":{"message":"invalid token","code":40003,"metadata":7}}`},
		{name: "metadata as an array", body: `{"error":{"message":"invalid token","code":40003,"metadata":["reason"]}}`},
		{name: "metadata as a boolean", body: `{"error":{"message":"invalid token","code":40003,"metadata":true}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := json.NewDecoder(strings.NewReader(tc.body))
			errResp, err := apiErrorFromResponse(http.StatusBadRequest, d)
			if err != nil {
				t.Fatalf("unexpected decode error: %v", err)
			}
			if errResp.ErrorField.Code != 40003 {
				t.Errorf("code = %d, want 40003", errResp.ErrorField.Code)
			}
			if errResp.ErrorField.Message != "invalid token" {
				t.Errorf("message = %q, want %q", errResp.ErrorField.Message, "invalid token")
			}
			if errResp.ErrorField.Metadata.Reason != "" {
				t.Errorf("reason = %q, want empty for a malformed metadata", errResp.ErrorField.Metadata.Reason)
			}
		})
	}
}

// TestUtilityResponseDecodesDestinationIPs pins the API field that carries the
// organization's effective Allowed Destination IP list. The list is enforced as a
// set of Firewall Mode exceptions, so a silent decode change - a renamed field, a
// nesting change - would leave endpoints blocking destinations the organization
// approved, with nothing in the logs to say why.
func TestUtilityResponseDecodesDestinationIPs(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "addresses and CIDRs of both families",
			body: `{"body":{"resolver":{"doh":"https://dns.controld.dev/abc","destination_ips":["203.0.113.10","198.51.100.0/24","2606:1a40::1","2001:db8::/48"]}},"success":true}`,
			want: []string{"203.0.113.10", "198.51.100.0/24", "2606:1a40::1", "2001:db8::/48"},
		},
		{
			name: "empty list - the API always sends the field",
			body: `{"body":{"resolver":{"doh":"https://dns.controld.dev/abc","destination_ips":[]}},"success":true}`,
			want: []string{},
		},
		{
			name: "field absent",
			body: `{"body":{"resolver":{"doh":"https://dns.controld.dev/abc"}},"success":true}`,
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ur := &utilityResponse{}
			require.NoError(t, json.Unmarshal([]byte(tc.body), ur))
			assert.Equal(t, tc.want, ur.Body.Resolver.DestinationIPs)
		})
	}
}
