package cli

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// udpSizeTestWriter captures messages without opening a real socket.
type udpSizeTestWriter struct {
	dns.ResponseWriter
	remote  net.Addr
	written *dns.Msg
}

func (w *udpSizeTestWriter) RemoteAddr() net.Addr {
	return w.remote
}

func (w *udpSizeTestWriter) WriteMsg(m *dns.Msg) error {
	w.written = m.Copy()
	return nil
}

func TestUDPSizeResponseWriter(t *testing.T) {
	tests := []struct {
		name     string
		remote   net.Addr
		ednsSize uint16
		maxSize  int
		wantTC   bool
	}{
		{
			name:    "UDP without EDNS",
			remote:  &net.UDPAddr{},
			maxSize: dns.MinMsgSize,
			wantTC:  true,
		},
		{
			name:     "UDP EDNS 1232",
			remote:   &net.UDPAddr{},
			ednsSize: 1232,
			maxSize:  1232,
			wantTC:   true,
		},
		{
			name:     "UDP EDNS 4096",
			remote:   &net.UDPAddr{},
			ednsSize: 4096,
			maxSize:  4096,
		},
		{
			name:     "TCP ignores UDP limit",
			remote:   &net.TCPAddr{},
			ednsSize: 1232,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := new(dns.Msg)
			request.SetQuestion("large.example.", dns.TypeTXT)
			if tt.ednsSize > 0 {
				request.SetEdns0(tt.ednsSize, true)
			}

			answer := new(dns.Msg)
			answer.SetReply(request)
			answer.Compress = true

			// Generate a response larger than 1232,
			// but smaller than 4096 bytes.
			for i := 0; i < 8; i++ {
				answer.Answer = append(answer.Answer, &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   "large.example.",
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Txt: []string{strings.Repeat("x", 220)},
				})
			}

			original := answer.Copy()
			originalWire, err := answer.Pack()
			if err != nil {
				t.Fatal(err)
			}
			capture := &udpSizeTestWriter{remote: tt.remote}
			writer := udpSizeResponseWriter{
				ResponseWriter: capture,
				request:        request,
			}

			if err := writer.WriteMsg(answer); err != nil {
				t.Fatal(err)
			}

			if capture.written == nil {
				t.Fatal("no response written")
			}

			got := capture.written
			wire, err := got.Pack()
			if err != nil {
				t.Fatal(err)
			}

			if tt.maxSize > 0 && len(wire) > tt.maxSize {
				t.Errorf("response size = %d, max = %d",
					len(wire), tt.maxSize)
			}
			if got.Truncated != tt.wantTC {
				t.Errorf("TC = %v, want %v",
					got.Truncated, tt.wantTC)
			}
			if !tt.wantTC && len(got.Answer) != len(original.Answer) {
				t.Errorf("answer count = %d, want %d",
					len(got.Answer), len(original.Answer))
			}
			currentWire, err := answer.Pack()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(originalWire, currentWire) {
				t.Error("original DNS response was modified")
			}
		})
	}
}
