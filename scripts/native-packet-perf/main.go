// Disposable Windows component measurement: real Wintun/helper/QUIC with a
// bounded UDP packet reflector. No Linux TUN, Internet path or TCP speed claim.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sanderstripa/connect-core/internal/ipvpn"
)

type reflector struct {
	packets chan []byte
	done    chan struct{}
	once    sync.Once
}

func (d *reflector) Close() error { d.once.Do(func() { close(d.done) }); return nil }
func (d *reflector) Read(out []byte) (int, error) {
	select {
	case <-d.done:
		return 0, io.EOF
	case p := <-d.packets:
		return copy(out, p), nil
	}
}
func (d *reflector) Write(p []byte) (int, error) {
	if len(p) < 28 || p[9] != 17 || binary.BigEndian.Uint16(p[22:24]) != 19082 {
		return len(p), nil
	}
	response := append([]byte(nil), p...)
	copy(response[12:16], p[16:20])
	copy(response[16:20], p[12:16])
	copy(response[20:22], p[22:24])
	copy(response[22:24], p[20:22])
	response[8] = 64
	response[10] = 0
	response[11] = 0
	response[26] = 0
	response[27] = 0
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(response[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(response[10:12], ^uint16(sum))
	select {
	case d.packets <- response:
	default:
	}
	return len(p), nil
}

func server(config string) error {
	data, err := os.ReadFile(config)
	if err != nil {
		return err
	}
	var cfg ipvpn.Config
	if err = json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	cfg.Endpoint = "127.0.0.1:17446"
	for _, p := range []*string{&cfg.Trust.CA, &cfg.Trust.Cert, &cfg.Trust.Key} {
		*p = filepath.Join(filepath.Dir(config), filepath.Base(*p))
	}
	policies, err := cfg.Validate(true)
	if err != nil {
		return err
	}
	tlsConfig, err := ipvpn.TLS(cfg, true)
	if err != nil {
		return err
	}
	listener, closeSocket, err := ipvpn.Listen(cfg.Endpoint, tlsConfig)
	if err != nil {
		return err
	}
	defer closeSocket()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { scanner := bufio.NewScanner(os.Stdin); scanner.Scan(); cancel() }()
	d := &reflector{packets: make(chan []byte, 4096), done: make(chan struct{})}
	fmt.Println("NATIVE_PACKET_REFLECTOR_READY")
	return ipvpn.Serve(ctx, listener, d, policies, &ipvpn.Stats{})
}

func measure() error {
	var sent, received, invalid atomic.Uint64
	var conns []*net.UDPConn
	for i := 0; i < 4; i++ {
		c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(10, 232, 0, 1), Port: 19082})
		if err != nil {
			return err
		}
		defer c.Close()
		_ = c.SetReadBuffer(8 << 20)
		conns = append(conns, c)
	}
	start := time.Now()
	deadline := start.Add(6 * time.Second)
	var readers, writers sync.WaitGroup
	for _, c := range conns {
		_ = c.SetReadDeadline(deadline.Add(time.Second))
		_ = c.SetWriteDeadline(deadline)
		readers.Add(1)
		writers.Add(1)
		go func(c *net.UDPConn) {
			defer readers.Done()
			p := make([]byte, 1100)
			for {
				n, err := c.Read(p)
				if err != nil {
					return
				}
				if n != 1000 || !bytes.Equal(p[:8], []byte("CCPERFv1")) {
					invalid.Add(1)
					continue
				}
				received.Add(1)
			}
		}(c)
		go func(c *net.UDPConn) {
			defer writers.Done()
			p := make([]byte, 1000)
			copy(p, "CCPERFv1")
			for sequence := uint64(0); time.Now().Before(deadline); sequence++ {
				binary.LittleEndian.PutUint64(p[8:16], sequence)
				if _, err := c.Write(p); err != nil {
					return
				}
				sent.Add(1)
			}
		}(c)
	}
	writers.Wait()
	readers.Wait()
	elapsed := time.Since(start).Seconds()
	if received.Load() == 0 || invalid.Load() != 0 {
		return errors.New("no valid reflected component payload")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"scope": "Windows Wintun/helper/QUIC + memory UDP reflector, no Linux TUN or Internet", "streams": 4, "payload_bytes": 1000, "seconds_including_drain": elapsed, "sent_packets": sent.Load(), "received_packets": received.Load(), "goodput_mbps_per_direction": float64(received.Load()) * 1000 * 8 / elapsed / 1e6, "invalid_packets": invalid.Load()})
}

func main() {
	if runtime.GOOS != "windows" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("CONNECT_DISPOSABLE_NATIVE_PERF") != "1" {
		fmt.Fprintln(os.Stderr, "Disposable Windows CI only")
		os.Exit(2)
	}
	var err error
	if len(os.Args) == 3 && os.Args[1] == "server" {
		err = server(os.Args[2])
	} else if len(os.Args) == 2 && os.Args[1] == "measure" {
		err = measure()
	} else {
		err = errors.New("expected server CONFIG or measure")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
