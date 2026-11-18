package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

func TestControlServer(t *testing.T) {
	f, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	s, err := newControlServer(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	pattern := "/ping"
	respBody := []byte("pong")
	s.register(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(respBody)
	}))
	if err := s.start(); err != nil {
		t.Fatal(err)
	}

	c := newControlClient(f.Name())
	resp, err := c.post(pattern, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("unepxected response code: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("content-type"); ct != contentTypeJson {
		t.Fatalf("unexpected content type: %s", ct)
	}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, respBody) {
		t.Errorf("unexpected response body, want: %q, got: %q", string(respBody), string(buf))
	}
	if err := s.stop(); err != nil {
		t.Fatal(err)
	}
}

// jsonStringTestPayload holds every byte class that a JSON string must escape
// and splits a multi-byte character across the chunk boundary, so a chunk that
// ends inside a character is covered.
func jsonStringTestPayload() []byte {
	var payload bytes.Buffer
	payload.WriteString("quotes \" backslash \\ tab\t return\r newline\n")
	payload.Write([]byte{0x00, 0x01, 0x1f})
	for payload.Len() < jsonStringChunkSize-1 {
		payload.WriteByte('x')
	}
	payload.WriteString("é日本語 and an emoji 🙂\n")
	payload.WriteString("the tail after the boundary\n")
	return payload.Bytes()
}

func Test_writeJSONString(t *testing.T) {
	payload := jsonStringTestPayload()
	var written bytes.Buffer

	if err := writeJSONString(&written, bytes.NewReader(payload)); err != nil {
		t.Fatalf("writeJSONString: %v", err)
	}

	var got string
	if err := json.Unmarshal(written.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal %d bytes: %v", written.Len(), err)
	}
	if got != string(payload) {
		t.Fatalf("the round trip returned %d bytes, want the %d bytes of the payload", len(got), len(payload))
	}
}

// newLogViewTestServer serves the log view handler of p on a temporary socket
// and returns a client of it.
func newLogViewTestServer(t *testing.T, p *prog) *controlClient {
	t.Helper()
	f, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatalf("temporary socket: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	s, err := newControlServer(f.Name())
	if err != nil {
		t.Fatalf("newControlServer: %v", err)
	}
	s.register(viewLogsPath, http.HandlerFunc(p.handleLogView))
	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = s.stop() })
	return newControlClient(f.Name())
}

func Test_logViewHandler(t *testing.T) {
	t.Run("answers the log as one JSON string", func(t *testing.T) {
		p := setupMemoryLogReaderTest(t)
		line := "a line with \"quotes\", a tab\there and 日本語\n"
		if _, err := p.internalLogWriter.Write([]byte(line)); err != nil {
			t.Fatalf("write the debug buffer: %v", err)
		}

		resp, err := newLogViewTestServer(t, p).post(viewLogsPath, nil)

		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if ct := resp.Header.Get("content-type"); ct != contentTypeJson {
			t.Fatalf("content type = %s, want %s", ct, contentTypeJson)
		}
		var view logViewResponse
		if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
			t.Fatalf("decode the answer: %v", err)
		}
		if !strings.Contains(view.Data, line) {
			t.Fatalf("the answer holds %.64q, want the line %q in it", view.Data, line)
		}
		if !strings.Contains(view.Data, logWriterLogEndMarker) {
			t.Fatalf("the answer holds no log end marker: %.64q", view.Data)
		}
	})

	t.Run("answers 301 without a log", func(t *testing.T) {
		origSilent, origCdUID := silent, cdUID
		t.Cleanup(func() { silent, cdUID = origSilent, origCdUID })
		silent, cdUID = false, ""
		p := &prog{cfg: &ctrld.Config{}}

		resp, err := newLogViewTestServer(t, p).post(viewLogsPath, nil)

		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMovedPermanently {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMovedPermanently)
		}
	})
}
