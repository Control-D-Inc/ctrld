package cli

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"testing"
)

func TestDelegatedLogSendAuditDoesNotAmplifyRejections(t *testing.T) {
	var audits int
	s := &logSendServer{gate: &logUploadGate{},
		collect: func(context.Context) (io.ReadCloser, error) { return nil, errors.New("synthetic failure") },
		audit: func(uid int64, status int) {
			audits++
			if uid != 501 || status != 412 {
				t.Errorf("audit uid=%d status=%d", uid, status)
			}
		},
	}
	for i := 0; i < 100; i++ {
		s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", sendLogsPath, nil))
		req := httptest.NewRequest("GET", sendLogsPath+"?full=1", nil).WithContext(context.WithValue(context.Background(), logSendPeerKey{}, uint32(501)))
		s.ServeHTTP(httptest.NewRecorder(), req)
	}
	if audits != 0 {
		t.Fatalf("rejected request audits=%d", audits)
	}
	req := httptest.NewRequest("POST", sendLogsPath, nil).WithContext(context.WithValue(context.Background(), logSendPeerKey{}, uint32(501)))
	for i := 0; i < 100; i++ {
		s.ServeHTTP(httptest.NewRecorder(), req)
	}
	if audits != 1 {
		t.Fatalf("admitted plus cooldown audits=%d, want 1", audits)
	}
}
