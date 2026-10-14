// Disposable CI probe: actual QUIC -> installer-owned TUN -> Linux UDP socket.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"net"
	"net/netip"
	"os"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("CONNECT_DISPOSABLE_INSTALL_TEST") != "1" || len(os.Args) != 2 {
		return errors.New("disposable CI opt-in required")
	}
	if os.Args[1] == "serve" {
		l, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.0.1"), Port: 18332})
		if e != nil {
			return e
		}
		defer l.Close()
		fmt.Println("ready")
		l.SetDeadline(time.Now().Add(3 * time.Minute))
		buf := make([]byte, 100)
		for {
			n, peer, e := l.ReadFromUDP(buf)
			if e != nil {
				return e
			}
			if !peer.IP.Equal(net.ParseIP("198.18.0.2")) {
				return errors.New("scoped VPS masquerade missing")
			}
			if _, e = l.WriteToUDP(buf[:n], peer); e != nil {
				return e
			}
		}
	}
	cfg, e := ipvpn.Load(os.Args[1])
	if e != nil {
		return e
	}
	policies, e := cfg.Validate(false)
	if e != nil {
		return e
	}
	tls, e := ipvpn.TLS(cfg, false)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	q, e := ipvpn.Dial(ctx, cfg.Endpoint, tls, policies[""].Device)
	if e != nil {
		return e
	}
	defer q.CloseWithError(0, "probe completed")
	dst := netip.MustParseAddr("198.18.0.1")
	payload := []byte("real-vps-probe")
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], policies[""].Device.AsSlice())
	copy(p[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(p[20:22], 25000)
	binary.BigEndian.PutUint16(p[22:24], 18332)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	if e = q.SendDatagram(p); e != nil {
		return e
	}
	reply, e := q.ReceiveDatagram(ctx)
	if e != nil {
		return e
	}
	if !policies[""].Allows(reply, false) || string(reply[28:]) != string(payload) {
		return errors.New("real TUN echo mismatch")
	}
	return nil
}
