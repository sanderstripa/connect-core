package ipvpn

import (
	"context"
	"errors"
	"github.com/apernet/quic-go"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestTransientDialErrorDoesNotRetryRevocationOrCrypto(t *testing.T) {
	for _, err := range []error{&quic.ApplicationError{ErrorCode: 4}, &quic.ApplicationError{ErrorCode: 1}, &quic.TransportError{ErrorCode: 0x12a}, errors.New("certificate mismatch")} {
		if TransientDialError(err) {
			t.Fatal("terminal rejection retried", err)
		}
	}
	if !TransientDialError(&quic.ApplicationError{ErrorCode: 3}) || !TransientDialError(&net.DNSError{IsTimeout: true}) {
		t.Fatal("transient startup failure not retried")
	}
}

func TestDialWithRetryCancelledImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	f := setup(t)
	if _, err := DialWithRetry(ctx, f.address, f.tls, netip.MustParseAddr("10.231.0.2"), nil); err == nil {
		t.Fatal("cancelled attempt succeeded")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation waited for retry budget")
	}
}

func TestDialWithRetryWaitsForOldDeviceSession(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	first, err := Dial(ctx, f.address, f.tls, netip.MustParseAddr("10.231.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	defer first.CloseWithError(0, "test done")
	attempts := 0
	recovered, err := DialWithRetry(ctx, f.address, f.tls, netip.MustParseAddr("10.231.0.2"), func(_ int, _ time.Duration) { attempts++; first.CloseWithError(0, "old session stopped") })
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.CloseWithError(0, "test done")
	if attempts == 0 {
		t.Fatal("busy device was not retried")
	}
}
