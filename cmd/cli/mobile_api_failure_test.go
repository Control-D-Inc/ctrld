package cli

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld/internal/controld"
)

func apiErrorResponse(status, code int, message string) *controld.ErrorResponse {
	r := &controld.ErrorResponse{StatusCode: status}
	r.ErrorField.Code = code
	r.ErrorField.Message = message
	return r
}

// apiStatusError is an answer whose body is not a JSON error, as
// controld returns it for an HTML page of a proxy or an empty body.
func apiStatusError(status int, decodeErr error) error {
	return fmt.Errorf("postUtilityAPI: %w", &controld.HTTPStatusError{StatusCode: status, Err: decodeErr})
}

func TestMobileAPIFailureLine(t *testing.T) {
	networkErr := &url.Error{Op: "Post", URL: "https://api.controld.com/utility", Err: errors.New("connection refused")}
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"rejected", apiErrorResponse(http.StatusUnauthorized, 0, "denied"), "provisioning failed: stage=api code=API_REJECTED (exit 31) http_status=401"},
		{"device deleted", apiErrorResponse(http.StatusNotFound, controld.InvalidConfigCode, "gone"), "provisioning failed: stage=api code=API_DEVICE_INVALID (exit 32) http_status=404"},
		{"rate limited", apiErrorResponse(http.StatusTooManyRequests, 0, "slow down"), "provisioning failed: stage=api code=API_RATE_LIMITED (exit 38) http_status=429"},
		{"server error", apiErrorResponse(http.StatusBadGateway, 0, "bad gateway"), "provisioning failed: stage=api code=API_UNAVAILABLE (exit 39) http_status=502"},
		{"maintenance", apiErrorResponse(http.StatusServiceUnavailable, controld.MaintenanceCode, controld.MaintenanceMessage), "provisioning failed: stage=api code=API_MAINTENANCE (exit 37) http_status=503"},
		{"request timeout", apiErrorResponse(http.StatusRequestTimeout, 0, "timeout"), "provisioning failed: stage=api code=API_UNREACHABLE (exit 30) http_status=408"},
		{"non-JSON 429", apiStatusError(http.StatusTooManyRequests, errors.New("invalid character '<' looking for beginning of value")), "provisioning failed: stage=api code=API_RATE_LIMITED (exit 38) http_status=429"},
		{"empty-body 503", apiStatusError(http.StatusServiceUnavailable, io.EOF), "provisioning failed: stage=api code=API_UNAVAILABLE (exit 39) http_status=503"},
		{"non-JSON 403 of a captive portal", apiStatusError(http.StatusForbidden, errors.New("invalid character '<' looking for beginning of value")), "provisioning failed: stage=api code=API_UNREACHABLE (exit 30) http_status=403"},
		{"network", fmt.Errorf("postUtilityAPI client.Do: %w", networkErr), "provisioning failed: stage=api code=API_UNREACHABLE (exit 30)"},
		{"no error", nil, "provisioning failed: stage=api code=UNCLASSIFIED (exit 59)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mobileAPIFailureLine(tc.err); got != tc.want {
				t.Errorf("mobileAPIFailureLine() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The API can echo the request back in its error text, and a transport error
// carries the URL. The Exit text goes to the app, which shows and logs it.
func TestMobileAPIFailureLineOmitsSecrets(t *testing.T) {
	const uid = "1e0rkx9a7tq"
	const token = "org-v1-secrettoken"
	oldUID, oldOrg := cdUID, cdOrg
	t.Cleanup(func() { cdUID, cdOrg = oldUID, oldOrg })
	cdUID, cdOrg = uid, token
	errs := []error{
		apiErrorResponse(http.StatusNotFound, 0, "resolver "+uid+" not found for "+token),
		&url.Error{Op: "Post", URL: "https://dns.controld.com/" + uid, Err: errors.New(token)},
		errors.New("failed to fetch resolver config for " + uid),
		apiStatusError(http.StatusForbidden, errors.New("page for "+uid+" "+token)),
	}
	for _, err := range errs {
		line := mobileAPIFailureLine(err)
		if strings.Contains(line, uid) || strings.Contains(line, token) {
			t.Errorf("Exit text %q leaks a secret from %q", line, err)
		}
	}
}
