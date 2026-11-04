//go:build darwin || linux

package cli

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestDelegatedLogSendListenerLimitAndClose(t *testing.T) {
	tree, _ := logSendFixture(t)
	path := filepath.Join(tree.root, "limit.sock")
	base, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	l := &logSendListener{Listener: base, slots: make(chan struct{}, 1), done: make(chan struct{})}
	defer l.Close()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if uid, err := logSendPeer(first); err != nil || uid != tree.uid {
		t.Fatalf("wrapped peer uid=%d err=%v", uid, err)
	}
	accepted := make(chan net.Conn, 1)
	failed := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			failed <- err
			return
		}
		accepted <- c
	}()
	client2, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()
	select {
	case c := <-accepted:
		c.Close()
		t.Fatal("connection limit bypassed")
	case <-time.After(20 * time.Millisecond):
	}
	first.Close()
	first.Close() // repeated closes must not release another connection's slot
	var second net.Conn
	select {
	case second = <-accepted:
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("slot not released")
	}
	defer second.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			c.Close()
		}
		failed <- err
	}()
	l.Close() // blocked acquisition must terminate, even while second is still open
	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("closed listener accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock accept")
	}
}
