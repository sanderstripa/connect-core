package ipvpn

import (
	"sync"
	"testing"
	"time"
)

func TestDenyDoesNotWaitForStalledPacketWrite(t *testing.T) {
	c := NewControl(map[string]Policy{"device": {}})
	closed := make(chan struct{})
	if !c.Admit("device", func() { close(closed) }) {
		t.Fatal("admission failed")
	}
	started, unblock := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.Transfer("device", true, 10, func() error { close(started); <-unblock; return nil })
	}()
	<-started
	denied := make(chan struct{})
	go func() { c.Deny("device"); close(denied) }()
	select {
	case <-denied:
	case <-time.After(time.Second):
		close(unblock)
		wg.Wait()
		t.Fatal("revocation blocked by TUN write")
	}
	<-closed
	called := false
	if c.Transfer("device", true, 1, func() error { called = true; return nil }) == nil || called {
		t.Fatal("post-revoke packet admitted")
	}
	if c.Admit("device", func() {}) {
		t.Fatal("post-revoke handshake admitted")
	}
	close(unblock)
	wg.Wait()
}
