package ipvpn

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDialPacketAuthenticatesAndOwnsSocket(t *testing.T) {
	for _, success := range []bool{true, false} {
		t.Run(map[bool]string{true: "accepted", false: "wrong-device-IP"}[success], func(t *testing.T) {
			f := setup(t)
			pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			remote, err := net.ResolveUDPAddr("udp4", f.address)
			if err != nil {
				t.Fatal(err)
			}
			want := netip.MustParseAddr("10.231.0.2")
			if !success {
				want = netip.MustParseAddr("10.231.0.3")
			}
			c, err := DialPacket(context.Background(), pc, remote, f.tls, want)
			if success {
				if err != nil {
					t.Fatal(err)
				}
				c.CloseWithError(0, "test done")
			} else if err == nil {
				c.CloseWithError(0, "test done")
				t.Fatal("lease mismatch accepted")
			}
			deadline := time.Now().Add(time.Second)
			for {
				_, err = pc.WriteTo([]byte("closed socket check"), remote)
				if err != nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("owned UDP socket remained open")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}
