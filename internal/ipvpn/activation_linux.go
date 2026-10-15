package ipvpn

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
)

var activation struct {
	once sync.Once
	file *os.File
	err  error
}

// Keep the inherited descriptor open for in-process stop/start. FilePacketConn
// duplicates it for each transport; no capability is added to the Core process.
func activatedPacketConn(address string) (net.PacketConn, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") == "" {
		return nil, nil
	}
	activation.once.Do(func() {
		if os.Getenv("LISTEN_FDS") != "1" {
			activation.err = errors.New("expected one owned UDP activation socket")
			return
		}
		activation.file = os.NewFile(3, "connect-data-activation")
		syscall.CloseOnExec(3)
		if activation.file == nil {
			activation.err = errors.New("activation socket unavailable")
		}
	})
	if activation.err != nil {
		return nil, activation.err
	}
	conn, err := net.FilePacketConn(activation.file)
	if err != nil {
		return nil, err
	}
	wanted, err := net.ResolveUDPAddr("udp4", address)
	actual, ok := conn.LocalAddr().(*net.UDPAddr)
	if err != nil || !ok || !actual.IP.Equal(wanted.IP) || actual.Port != wanted.Port {
		conn.Close()
		return nil, errors.New("activated UDP endpoint does not match owned configuration")
	}
	if udp, ok := conn.(*net.UDPConn); ok {
		raw, e := udp.SyscallConn()
		if e == nil {
			var receive, send int
			_ = raw.Control(func(fd uintptr) {
				receive, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
				send, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
			})
			activatedReceiveBuffer.Store(int64(receive))
			activatedSendBuffer.Store(int64(send))
			fmt.Fprintf(os.Stderr, "CONNECT UDP activation: receive_buffer_bytes=%d send_buffer_bytes=%d\n", receive, send)
		}
	}
	return conn, nil
}
