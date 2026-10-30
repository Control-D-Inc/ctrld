package controld

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func maintenanceErr(status, code int, message string) *ErrorResponse {
	e := &ErrorResponse{StatusCode: status}
	e.ErrorField.Code = code
	e.ErrorField.Message = message
	return e
}

// The message the API answered with during the reported incident, verbatim.
const reportedMaintenanceMessage = "Maintenance is in progress. Please try again later."

func TestIsMaintenanceByMessage(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"the reported answer", maintenanceErr(http.StatusServiceUnavailable, 0, reportedMaintenanceMessage), true},
		{"carried on a client-error status", maintenanceErr(http.StatusBadRequest, 40003, reportedMaintenanceMessage), true},
		{"wrapped", fmt.Errorf("fetching config: %w", maintenanceErr(503, 0, reportedMaintenanceMessage)), true},
		{"a device rejection is not maintenance", maintenanceErr(http.StatusNotFound, InvalidConfigCode, "device does not exist"), false},
		{"an empty message is not maintenance", maintenanceErr(http.StatusBadGateway, 0, ""), false},
		{"a plain error is not maintenance", errors.New("dial tcp: connection refused"), false},
		{"no error is not maintenance", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsMaintenance(tc.err); got != tc.want {
				t.Fatalf("IsMaintenance() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIsMaintenanceByCode covers the dedicated code. It must classify an
// answer that carries no recognizable message, must not stop recognizing the
// message form, which older deployments keep sending, and must not swallow
// the neighbouring codes that mean something else.
func TestIsMaintenanceByCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"hard maintenance code", maintenanceErr(http.StatusServiceUnavailable, 50302, "scheduled downtime"), true},
		{"message form without the code", maintenanceErr(http.StatusServiceUnavailable, 0, reportedMaintenanceMessage), true},
		{"service unavailable is a failure", maintenanceErr(http.StatusServiceUnavailable, 50301, "Service unavailable"), false},
		{"read-only mode", maintenanceErr(http.StatusInternalServerError, 50003,
			"Maintenance is in progress, cannot make any modifications. Please try again soon."), false},
		{"deleted device", maintenanceErr(http.StatusNotFound, InvalidConfigCode, "device does not exist"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsMaintenance(tc.err); got != tc.want {
				t.Fatalf("IsMaintenance() = %v, want %v", got, tc.want)
			}
		})
	}
}

// The API's hard maintenance answer, byte for byte as api_public/index.php
// writes it. "body" is an empty JSON array rather than an object, so the error
// decode must not depend on it.
func TestIsMaintenanceFromHardMaintenanceResponse(t *testing.T) {
	const body = `{"body":[],"success":false,"error":{"date":"Mon, 05 Oct 2026 10:00:00 +0000",` +
		`"message":"Maintenance is in progress. Please try again later.","code":50302}}`
	errResp, err := apiErrorFromResponse(http.StatusServiceUnavailable, json.NewDecoder(strings.NewReader(body)))
	if err != nil {
		t.Fatalf("decoding the maintenance answer: %v", err)
	}
	if errResp.StatusCode != http.StatusServiceUnavailable || errResp.ErrorField.Code != MaintenanceCode {
		t.Fatalf("errResp = %+v", errResp)
	}
	if !IsMaintenance(fmt.Errorf("fetching config: %w", errResp)) {
		t.Fatal("the hard maintenance answer was not classified as maintenance")
	}
}
