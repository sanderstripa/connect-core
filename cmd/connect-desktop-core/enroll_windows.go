//go:build windows

package main

import (
	"context"
	"github.com/sanderstripa/connect-core/internal/access"
	"github.com/sanderstripa/connect-core/internal/desktop"
	"os"
	"time"
)

func (w *worker) enroll(path, link string) {
	invitation, e := access.Parse(link)
	if e != nil {
		w.mu.Lock()
		w.code = 4
		w.mu.Unlock()
		return
	}
	w.stop()
	ctx, cancel := context.WithCancel(context.Background())
	w.mu.Lock()
	w.cancel = cancel
	w.done = make(chan struct{})
	done := w.done
	w.state = desktop.Enrolling
	w.code = 0
	w.mu.Unlock()
	go func() {
		defer close(done)
		key, csr, e := access.KeyAndCSR(invitation.Token)
		pending := path + ".pending"
		if e == nil {
			var sealed []byte
			sealed, e = protect(key, false)
			if e == nil {
				e = os.WriteFile(pending, sealed, 0600)
			}
		}
		var b bundle
		if e == nil {
			var reply access.Response
			reply, e = access.Redeem(ctx, invitation, csr)
			if e == nil {
				b = bundle{Config: reply.Config, CA: []byte(reply.CA), Cert: []byte(reply.Certificate), Key: key}
				_, e = b.tls()
			}
		}
		if e == nil {
			e = save(path, b)
		}
		w.mu.Lock()
		if e == nil {
			w.b = b
			w.state = desktop.Ready
			w.code = 0
			w.stats = nil
			w.since = time.Time{}
			w.elapsed = 0
			w.dnsRTT = 0
			_ = os.Remove(pending)
		} else if ctx.Err() != nil {
			w.state = desktop.Ready
			w.code = 0
		} else {
			w.state = desktop.Failed
			w.code = 4
		}
		w.mu.Unlock()
		w.emit()
	}()
}
