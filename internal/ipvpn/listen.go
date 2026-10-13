package ipvpn

import (
	"crypto/tls"
	"errors"
	"github.com/quic-go/quic-go"
	"net"
	"sync"
)

// Listen owns its socket and transport. Listener.Close alone leaves accepted
// QUIC connections alive; explicit ownership makes component restart reliable.
func Listen(address string, t *tls.Config) (*quic.Listener, func() error, error) {
	socket, e := net.ListenPacket("udp4", address)
	if e != nil {
		return nil, nil, e
	}
	transport := &quic.Transport{Conn: socket}
	l, e := transport.Listen(t, QUIC())
	if e != nil {
		_ = transport.Close()
		_ = socket.Close()
		return nil, nil, e
	}
	var once sync.Once
	var result error
	close := func() error {
		once.Do(func() { result = errors.Join(l.Close(), transport.Close(), socket.Close()) })
		return result
	}
	return l, close, nil
}
