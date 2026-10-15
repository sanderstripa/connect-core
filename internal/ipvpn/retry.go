package ipvpn

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/quic-go/quic-go"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// TransientDialError never retries certificate, protocol or access rejection.
// A busy device may be a previous QUIC session waiting for its idle deadline;
// retrying does not evict that session or change certificate authorization.
func TransientDialError(err error) bool {
	var app *quic.ApplicationError
	if errors.As(err, &app) {
		return app.ErrorCode == 3
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}
	var network net.Error
	return errors.As(err, &network) && network.Timeout()
}

func DialWithRetry(ctx context.Context, address string, t *tls.Config, want netip.Addr, retry func(int, time.Duration)) (*quic.Conn, error) {
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var last error
	for attempt := 1; ; attempt++ {
		c, err := Dial(deadline, address, t, want)
		if err == nil {
			return c, nil
		}
		last = err
		if !TransientDialError(err) || deadline.Err() != nil {
			return nil, last
		}
		delay := time.Duration(attempt) * 250 * time.Millisecond
		if delay > 2*time.Second {
			delay = 2 * time.Second
		}
		if retry != nil {
			retry(attempt, delay)
		}
		timer := time.NewTimer(delay)
		select {
		case <-deadline.Done():
			timer.Stop()
			return nil, last
		case <-timer.C:
		}
	}
}
