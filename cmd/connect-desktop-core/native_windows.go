//go:build windows

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Microsoft/go-winio"
	"github.com/sanderstripa/connect-core/internal/desktop"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type nativeBridge struct {
	conn    net.Conn
	mu      sync.Mutex
	writing sync.Mutex
	active  *nativeView
	done    chan struct{}
	ack     chan uint32
	stats   *ipvpn.Stats
}
type nativeView struct {
	bridge  *nativeBridge
	packets chan []byte
	done    chan struct{}
	once    sync.Once
}

func elevatedHelper(args string) error {
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	path := filepath.Join(filepath.Dir(exe), "ConnectCoreNetwork.exe")
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(path)
	params, _ := windows.UTF16PtrFromString(args)
	return windows.ShellExecute(0, verb, file, params, nil, windows.SW_HIDE)
}
func openHelper(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, e
	}
	var random [32]byte
	if _, e = rand.Read(random[:]); e != nil {
		return nil, e
	}
	pipe := `\\.\pipe\ConnectCore-` + hex.EncodeToString(random[:])
	listener, e := winio.ListenPipe(pipe, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + user.User.Sid.String() + ")(A;;GA;;;BA)(A;;GA;;;SY)", InputBufferSize: 65536, OutputBufferSize: 65536})
	if e != nil {
		return nil, e
	}
	defer listener.Close()
	type accepted struct {
		conn net.Conn
		err  error
	}
	ready := make(chan accepted, 1)
	go func() {
		conn, e := listener.Accept()
		if conn != nil {
			select {
			case <-ctx.Done():
				conn.Close()
			default:
			}
		}
		ready <- accepted{conn, e}
	}()
	shell := make(chan error, 1)
	go func() { shell <- elevatedHelper("\"" + pipe + "\" " + strconv.Itoa(os.Getpid())) }()
	var conn net.Conn
	for conn == nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case e := <-shell:
			if e != nil {
				return nil, e
			}
		case result := <-ready:
			if result.err != nil {
				return nil, result.err
			}
			conn = result.conn
		}
	}
	success := false
	defer func() {
		if !success {
			conn.Close()
		}
	}()
	fd, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return nil, errors.New("pipe handle unavailable")
	}
	var pid uint32
	if e = windows.GetNamedPipeClientProcessId(windows.Handle(fd.Fd()), &pid); e != nil {
		return nil, e
	}
	p, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		return nil, e
	}
	defer windows.CloseHandle(p)
	var token windows.Token
	if e = windows.OpenProcessToken(p, windows.TOKEN_QUERY, &token); e != nil {
		return nil, e
	}
	elevated := token.IsElevated()
	token.Close()
	if !elevated {
		return nil, errors.New("network helper must have an elevated token")
	}
	name := make([]uint16, 32768)
	size := uint32(len(name))
	if e = windows.QueryFullProcessImageName(p, 0, &name[0], &size); e != nil {
		return nil, e
	}
	exe, _ := os.Executable()
	expected := filepath.Join(filepath.Dir(exe), "ConnectCoreNetwork.exe")
	if !strings.EqualFold(windows.UTF16ToString(name[:size]), expected) {
		return nil, errors.New("network helper identity mismatch")
	}
	success = true
	return conn, nil
}
func openNative(ctx context.Context, cfg ipvpn.Config, stats *ipvpn.Stats) (*nativeBridge, error) {
	if cfg.Network == nil {
		return nil, errors.New("explicit OS network policy required")
	}
	if _, e := cfg.Validate(false); e != nil {
		return nil, e
	}
	conn, e := openHelper(ctx)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			conn.Close()
		}
	}()
	plan := make([]byte, 20)
	binary.LittleEndian.PutUint32(plan, 1)
	ep := netip.MustParseAddrPort(cfg.Endpoint)
	a := ep.Addr().As4()
	copy(plan[4:8], a[:])
	ip := netip.MustParseAddr(cfg.DeviceIP).As4()
	copy(plan[8:12], ip[:])
	dns := netip.MustParseAddr(cfg.Network.DNS).As4()
	copy(plan[12:16], dns[:])
	binary.LittleEndian.PutUint16(plan[16:18], ep.Port())
	binary.LittleEndian.PutUint16(plan[18:], 1)
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if e = desktop.Write(conn, desktop.ConfigureNetwork, plan); e != nil {
		return nil, e
	}
	kind, payload, e := desktop.Read(conn)
	if e != nil || kind != desktop.Status || len(payload) != desktop.StatusSize || binary.LittleEndian.Uint32(payload) != desktop.Connected {
		if e == nil && len(payload) == desktop.StatusSize {
			// Numeric OS stage diagnostics contain neither secrets nor paths.
			fmt.Fprintf(os.Stderr, "CONNECT network setup: Windows=%d stage=%d protection=%d\n", binary.LittleEndian.Uint32(payload[8:]), binary.LittleEndian.Uint32(payload[16:]), binary.LittleEndian.Uint32(payload[32:]))
			return nil, fmt.Errorf("network helper setup failed: Windows=%d stage=%d protection=%d", binary.LittleEndian.Uint32(payload[8:]), binary.LittleEndian.Uint32(payload[16:]), binary.LittleEndian.Uint32(payload[32:]))
		}
		return nil, errors.New("Wintun/network setup failed; inspect or recover retained guard")
	}
	conn.SetDeadline(time.Time{})
	b := &nativeBridge{conn: conn, done: make(chan struct{}), ack: make(chan uint32, 1), stats: stats}
	success = true
	go b.read()
	return b, nil
}
func (b *nativeBridge) read() {
	defer close(b.done)
	for {
		kind, p, e := desktop.Read(b.conn)
		if e != nil {
			return
		}
		if kind == desktop.NetworkCounters && len(p) == 24 {
			fmt.Fprintf(os.Stderr, "CONNECT Wintun counters: packets=%d bytes=%d polls=%d\n", binary.LittleEndian.Uint64(p), binary.LittleEndian.Uint64(p[8:]), binary.LittleEndian.Uint64(p[16:]))
			continue
		}
		if kind == desktop.Status && len(p) == desktop.StatusSize {
			select {
			case b.ack <- binary.LittleEndian.Uint32(p):
			default:
			}
			continue
		}
		if kind != desktop.FromTUN || len(p) > ipvpn.MTU || len(p) < 20 {
			return
		}
		b.mu.Lock()
		if b.active != nil {
			select {
			case b.active.packets <- p:
			default:
				b.stats.Dropped.Add(1)
			}
		} else {
			b.stats.Dropped.Add(1)
		}
		b.mu.Unlock()
	}
}
func (b *nativeBridge) view() *nativeView {
	v := &nativeView{bridge: b, packets: make(chan []byte, 64), done: make(chan struct{})}
	b.mu.Lock()
	b.active = v
	b.mu.Unlock()
	return v
}
func (v *nativeView) Read(p []byte) (int, error) {
	select {
	case <-v.done:
		return 0, io.EOF
	case <-v.bridge.done:
		return 0, io.EOF
	case pkt := <-v.packets:
		return copy(p, pkt), nil
	}
}
func (v *nativeView) Write(p []byte) (int, error) {
	select {
	case <-v.done:
		return 0, io.EOF
	default:
	}
	v.bridge.writing.Lock()
	defer v.bridge.writing.Unlock()
	if e := desktop.Write(v.bridge.conn, desktop.ToTUN, p); e != nil {
		return 0, e
	}
	return len(p), nil
}

// Session Close only detaches the packet pump. The privileged adapter and WFP
// guard survive transport failure, so Windows cannot silently fall back direct.
func (v *nativeView) Close() error {
	v.once.Do(func() {
		fmt.Fprintf(os.Stderr, "CONNECT network counters: sent=%d received=%d dropped=%d\n", v.bridge.stats.Sent.Load(), v.bridge.stats.Received.Load(), v.bridge.stats.Dropped.Load())
		v.bridge.mu.Lock()
		if v.bridge.active == v {
			v.bridge.active = nil
		}
		close(v.done)
		v.bridge.mu.Unlock()
	})
	return nil
}
func (b *nativeBridge) shutdown() error {
	b.writing.Lock()
	e := desktop.Write(b.conn, desktop.Exit, nil)
	b.writing.Unlock()
	if e == nil {
		select {
		case state := <-b.ack:
			if state != desktop.Ready {
				e = errors.New("network rollback incomplete")
			}
		case <-b.done:
			select {
			case state := <-b.ack:
				if state != desktop.Ready {
					e = errors.New("network rollback incomplete")
				}
			default:
				e = errors.New("helper stopped without rollback confirmation")
			}
		case <-time.After(6 * time.Second):
			e = errors.New("network rollback timed out")
		}
	}
	b.conn.Close()
	return e
}
func recoverNative(ctx context.Context) error {
	conn, e := openHelper(ctx)
	if e != nil {
		return e
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if e = desktop.Write(conn, desktop.Recover, nil); e != nil {
		return e
	}
	kind, p, e := desktop.Read(conn)
	if e != nil || kind != desktop.Status || len(p) != desktop.StatusSize || binary.LittleEndian.Uint32(p) != desktop.Ready {
		return errors.New("explicit network recovery failed")
	}
	return nil
}
