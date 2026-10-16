//go:build windows

// A non-elevated CONNECT IP v2 worker. System networking is delegated to a
// separately elevated, capability-limited helper; packet mode needs no helper.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/sanderstripa/connect-core/internal/access"
	"github.com/sanderstripa/connect-core/internal/desktop"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"golang.org/x/sys/windows"
)

type bundle struct {
	Config        ipvpn.Config
	CA, Cert, Key []byte
}
type packetDevice struct {
	packets chan []byte
	done    chan struct{}
	once    sync.Once
}

func newDevice() *packetDevice {
	return &packetDevice{packets: make(chan []byte, 1), done: make(chan struct{})}
}
func (d *packetDevice) Read(b []byte) (int, error) {
	select {
	case p := <-d.packets:
		return copy(b, p), nil
	case <-d.done:
		return 0, io.EOF
	}
}
func (d *packetDevice) Write(b []byte) (int, error) { return len(b), nil }
func (d *packetDevice) Close() error                { d.once.Do(func() { close(d.done) }); return nil }

func automaticVPN(c *ipvpn.Config) {
	if c.Environment == "managed-vps" && c.Network == nil {
		dns := "1.1.1.1"
		if endpoint, e := netip.ParseAddrPort(c.Endpoint); e == nil && endpoint.Addr().String() == dns {
			dns = "9.9.9.9"
		}
		c.Network = &ipvpn.NetworkPolicy{Mode: "system-vpn", DNS: dns}
	}
}

func load(path string) (bundle, error) {
	var b bundle
	c, e := ipvpn.Load(path)
	if e != nil {
		return b, e
	}
	automaticVPN(&c)
	if _, e = c.Validate(false); e != nil {
		return b, e
	}
	if len(c.Clients) != 0 || c.Trust.Version != 1 || c.Trust.ServerName == "" {
		return b, errors.New("not a client configuration")
	}
	b.Config = c
	for name, dst := range map[string]*[]byte{c.Trust.CA: &b.CA, c.Trust.Cert: &b.Cert, c.Trust.Key: &b.Key} {
		if !filepath.IsAbs(name) {
			name = filepath.Join(filepath.Dir(path), name)
		}
		f, e := os.Open(name)
		if e != nil {
			return b, e
		}
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() > 65536 {
			f.Close()
			return b, errors.New("invalid credential file")
		}
		*dst, e = io.ReadAll(io.LimitReader(f, 65537))
		f.Close()
		if e != nil {
			return b, e
		}
	}
	_, e = b.tls()
	return b, e
}
func (b bundle) tls() (*tls.Config, error) {
	pair, e := tls.X509KeyPair(b.Cert, b.Key)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, e
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errors.New("expired client certificate")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(b.CA) {
		return nil, errors.New("invalid CA")
	}
	intermediates := x509.NewCertPool()
	for _, raw := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, err
		}
		intermediates.AddCert(cert)
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return nil, e
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: roots, ServerName: b.Config.Trust.ServerName, NextProtos: []string{ipvpn.ALPN}, SessionTicketsDisabled: true}, nil
}
func blob(b []byte) windows.DataBlob {
	if len(b) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}
func protect(b []byte, decrypt bool) ([]byte, error) {
	in := blob(b)
	var out windows.DataBlob
	var e error
	if decrypt {
		e = windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		e = windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if e != nil {
		return nil, e
	}
	defer windows.LocalFree(windows.Handle(uintptrPointer(out.Data)))
	return copyBlob(out), nil
}
func storePath() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, e := token.GetTokenUser()
	if e != nil {
		return "", e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if e != nil {
		return "", e
	}
	root := filepath.Join(os.Getenv("LOCALAPPDATA"), "ConnectCoreLab")
	p, e := windows.UTF16PtrFromString(root)
	if e != nil {
		return "", e
	}
	e = windows.CreateDirectory(p, &windows.SecurityAttributes{Length: uint32(unsafeSizeSA()), SecurityDescriptor: sd})
	if e != nil && e != windows.ERROR_ALREADY_EXISTS {
		return "", e
	}
	// Reapply a protected current-user DACL even to an existing directory.
	acl, _, e := sd.DACL()
	if e != nil {
		return "", e
	}
	if e = windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); e != nil {
		return "", e
	}
	return filepath.Join(root, "profile.dpapi"), nil
}
func save(path string, b bundle) error {
	raw, e := json.Marshal(b)
	if e != nil {
		return e
	}
	sealed, e := protect(raw, false)
	clear(raw)
	if e != nil {
		return e
	}
	tmp := path + ".new"
	if e = os.WriteFile(tmp, sealed, 0600); e != nil {
		return e
	}
	a, _ := windows.UTF16PtrFromString(tmp)
	z, _ := windows.UTF16PtrFromString(path)
	return windows.MoveFileEx(a, z, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

type worker struct {
	mu          sync.Mutex
	b           bundle
	state, code uint32
	cancel      context.CancelFunc
	done        chan struct{}
	device      *packetDevice
	native      *nativeBridge
	stats       *ipvpn.Stats
	since       time.Time
	elapsed     time.Duration
	dnsRTT      uint64
	fingerprint string
	output      sync.Mutex
	writer      io.Writer
}

func (w *worker) emit() {
	w.mu.Lock()
	p := make([]byte, desktop.StatusSize)
	binary.LittleEndian.PutUint32(p, w.state)
	binary.LittleEndian.PutUint32(p[4:], w.code)
	if w.stats != nil {
		binary.LittleEndian.PutUint64(p[8:], w.stats.SentBytes.Load())
		binary.LittleEndian.PutUint64(p[16:], w.stats.ReceivedBytes.Load())
	}
	elapsed := w.elapsed
	if w.state == desktop.Connected {
		elapsed = time.Since(w.since)
	}
	binary.LittleEndian.PutUint64(p[24:], uint64(elapsed.Milliseconds()))
	mode := uint32(0)
	if w.b.Config.Network != nil {
		mode = 2
	}
	if w.native != nil {
		mode = 1
		binary.LittleEndian.PutUint32(p[164:], w.native.helperPID)
	}
	if w.code == 5 {
		mode = 3
	}
	binary.LittleEndian.PutUint32(p[32:], mode)
	if w.state == desktop.Enrolling {
		copy(p[36:164], w.fingerprint)
	} else {
		copy(p[36:164], w.b.Config.Endpoint)
	}
	binary.LittleEndian.PutUint64(p[168:], w.dnsRTT)
	w.mu.Unlock()
	w.output.Lock()
	defer w.output.Unlock()
	writer := w.writer
	if writer == nil {
		writer = os.Stdout
	}
	if desktop.Write(writer, desktop.Status, p) != nil {
		os.Exit(0)
	}
}
func (w *worker) stop() {
	w.mu.Lock()
	cancel, done := w.cancel, w.done
	w.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	w.mu.Lock()
	native, oldCode := w.native, w.code
	w.mu.Unlock()
	var cleanup error
	if native != nil {
		cleanup = native.shutdown()
	}
	if native == nil && oldCode == 5 {
		cleanup = errors.New("explicit recovery required")
	}
	w.mu.Lock()
	w.cancel = nil
	w.device = nil
	w.state = desktop.Ready
	if w.b.Config.Version != 2 {
		w.state = desktop.Idle
	}
	if cleanup == nil {
		w.native = nil
		w.code = 0
	} else {
		w.state = desktop.Failed
		w.code = 5
	}
	w.mu.Unlock()
}
func (w *worker) connect() {
	w.stop()
	w.mu.Lock()
	if w.code == 5 {
		w.mu.Unlock()
		return
	}
	automaticVPN(&w.b.Config)
	b := w.b
	if b.Config.Version != 2 {
		w.state = desktop.Failed
		w.code = 1
		w.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.done = make(chan struct{})
	done := w.done
	w.state = desktop.Connecting
	w.code = 0
	w.stats = &ipvpn.Stats{}
	stats := w.stats
	w.since = time.Time{}
	w.elapsed = 0
	w.dnsRTT = 0
	w.mu.Unlock()
	go func() {
		defer close(done)
		t, e := b.tls()
		var native *nativeBridge
		setupFailed := false
		if e == nil && b.Config.Network != nil {
			native, e = openNative(ctx, b.Config, stats)
			setupFailed = e != nil
			w.mu.Lock()
			w.native = native
			w.mu.Unlock()
		}
		if e == nil {
			var policies map[string]ipvpn.Policy
			policies, e = b.Config.Validate(false)
			if e == nil {
				dial := ipvpn.Dial
				if native != nil {
					dial = native.dial
				}
				c, err := ipvpn.DialWithRetryUsing(ctx, b.Config.Endpoint, t, policies[""].Device, func(attempt int, delay time.Duration) {
					fmt.Fprintf(os.Stderr, "CONNECT transient connection retry: attempt=%d delay_ms=%d\n", attempt, delay.Milliseconds())
				}, dial)
				e = err
				if e == nil {
					var d ipvpn.Device
					var packet *packetDevice
					if native != nil {
						d = native.view()
					} else {
						packet = newDevice()
						d = packet
					}
					w.mu.Lock()
					w.device = packet
					w.state = desktop.Connected
					w.since = time.Now()
					w.mu.Unlock()
					w.emit()
					e = ipvpn.Client(ctx, c, d, policies[""], stats)
				}
			}
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		w.device = nil
		if !w.since.IsZero() {
			w.elapsed = time.Since(w.since)
		}
		if ctx.Err() != nil {
			w.state = desktop.Ready
			w.code = 0
			// Cancellation can race with privileged setup. Without a bridge we
			// cannot prove rollback; retain the explicit recovery requirement.
			if setupFailed && !errors.Is(e, windows.ERROR_CANCELLED) {
				w.state = desktop.Failed
				w.code = 5
			}
		} else {
			w.state = desktop.Failed
			w.code = 2
			if native != nil {
				select {
				case <-native.done:
					w.code = 5
				default:
				}
			}
			if setupFailed {
				w.code = 5
				if errors.Is(e, windows.ERROR_CANCELLED) {
					w.code = 7
				}
			}
			if e != nil {
				fmt.Fprintf(os.Stderr, "CONNECT connection failure: type=%T setup_failed=%t transient=%t\n", e, setupFailed, ipvpn.TransientDialError(e))
				var application *quic.ApplicationError
				if errors.As(e, &application) {
					fmt.Fprintf(os.Stderr, "CONNECT server rejection: code=%d remote=%t\n", application.ErrorCode, application.Remote)
				}
				var certErr *tls.CertificateVerificationError
				if errors.As(e, &certErr) {
					w.code = 3
				}
			}
		}
	}()
}

// An explicit diagnostic sends a real, policy-checked UDP IP packet through Core.
// Port 18082 is the repository's lab UDP echo fixture. No direct socket fallback.
func (w *worker) probe() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state == desktop.Connected && w.b.Config.Network != nil {
		go w.probeDNS(w.b.Config, w.stats)
		return
	}
	if w.state != desktop.Connected || w.device == nil {
		return
	}
	c := w.b.Config
	dst := netip.MustParsePrefix(c.Destinations[0]).Addr().As4()
	src := netip.MustParseAddr(c.DeviceIP).As4()
	p := make([]byte, 44)
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[20:], 49152)
	binary.BigEndian.PutUint16(p[22:], 18082)
	binary.BigEndian.PutUint16(p[24:], 24)
	copy(p[28:], "CONNECT CORE LAB")
	var s uint32
	for i := 0; i < 20; i += 2 {
		s += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	binary.BigEndian.PutUint16(p[10:], ^uint16(s))
	select {
	case w.device.packets <- p:
	default:
	}
}
func main() {
	// Library diagnostics cannot contaminate the binary IPC or expose credentials.
	log.SetOutput(io.Discard)
	// This process is exclusively launched with inherited, private anonymous pipes.
	if len(os.Args) != 2 || os.Args[1] != "--ipc" {
		return
	}
	path, e := storePath()
	if e != nil {
		return
	}
	w := &worker{state: desktop.Idle}
	if sealed, e := os.ReadFile(path); e == nil && len(sealed) < 300000 {
		if raw, e := protect(sealed, true); e == nil {
			if json.Unmarshal(raw, &w.b) == nil {
				automaticVPN(&w.b.Config)
				if _, e = w.b.Config.Validate(false); e == nil {
					if _, e = w.b.tls(); e == nil {
						w.state = desktop.Ready
					}
				}
			}
			clear(raw)
		}
	}
	defer w.stop()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	quit := make(chan struct{})
	defer close(quit)
	go func() {
		for {
			select {
			case <-tick.C:
				w.emit()
			case <-quit:
				return
			}
		}
	}()
	w.emit()
	for {
		kind, p, e := desktop.Read(os.Stdin)
		if e != nil {
			return
		}
		if kind != desktop.Import && kind != desktop.ImportURI && kind != desktop.ImportQR && kind != desktop.ConfigureDNS && len(p) != 0 {
			return
		}
		switch kind {
		case desktop.ConfigureDNS:
			w.stop()
			w.mu.Lock()
			b, recoveryRequired := w.b, w.code == 5
			w.mu.Unlock()
			if recoveryRequired {
				w.emit()
				continue
			}
			b.Config.Network = &ipvpn.NetworkPolicy{Mode: "system-vpn", DNS: string(p)}
			_, err := b.Config.Validate(false)
			if b.Config.Environment != "managed-vps" || len(p) > 15 {
				err = errors.New("explicit managed profile DNS required")
			}
			if err == nil {
				err = save(path, b)
			}
			w.mu.Lock()
			if err != nil {
				w.code = 12
			} else {
				w.b = b
				w.state = desktop.Ready
				w.code = 0
			}
			w.mu.Unlock()
			if err == nil {
				w.connect()
			}
		case desktop.Recover:
			w.stop()
			err := recoverNative(context.Background())
			w.mu.Lock()
			if err == nil {
				w.native = nil
				w.state = desktop.Ready
				w.code = 0
			} else {
				w.state = desktop.Failed
				w.code = 5
			}
			w.mu.Unlock()
		case desktop.ImportURI, desktop.ImportQR:
			link := string(p)
			if kind == desktop.ImportQR {
				link, e = access.ReadQR(link)
				if e != nil {
					w.mu.Lock()
					w.code = 4
					w.mu.Unlock()
					w.emit()
					continue
				}
			}
			w.enroll(path, link)
		case desktop.Import:
			w.stop()
			w.mu.Lock()
			recoveryRequired := w.code == 5
			w.mu.Unlock()
			if recoveryRequired {
				w.emit()
				continue
			}
			b, e := load(string(p))
			if e == nil {
				e = save(path, b)
			}
			w.mu.Lock()
			if e != nil {
				w.code = 1
			} else {
				w.b = b
				w.state = desktop.Ready
				w.code = 0
				w.stats = nil
				w.since = time.Time{}
				w.elapsed = 0
				w.dnsRTT = 0
			}
			w.mu.Unlock()
		case desktop.Connect:
			w.connect()
		case desktop.Disconnect:
			w.stop()
		case desktop.Probe:
			w.probe()
		case desktop.Exit:
			return
		default:
			return
		}
		w.emit()
	}
}
