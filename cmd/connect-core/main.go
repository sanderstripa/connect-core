package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/sanderstripa/connect-core/internal/core"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"github.com/sanderstripa/connect-core/internal/lab"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: connect-core {init-lab|server|client|http-lab|ip-server|ip-client|ip-client-managed|ip-client-reconnect} {directory|config.json|127.0.0.1:port}")
	}
	mode, path := os.Args[1], os.Args[2]
	if mode == "ip-client-managed" || mode == "ip-client-reconnect" {
		return runManaged(path, mode == "ip-client-managed")
	}
	if mode == "init-lab" {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			return fmt.Errorf("choose a new lab directory")
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		s, c, err := lab.Generate(absolute)
		if err != nil {
			return err
		}
		for name, cfg := range map[string]core.Config{"server.json": s, "client.json": c} {
			b, e := json.MarshalIndent(cfg, "", "  ")
			if e != nil {
				return e
			}
			if e = os.WriteFile(filepath.Join(absolute, name), b, 0600); e != nil {
				return e
			}
		}
		ipServer := ipvpn.Config{Version: 2, Environment: "isolated-lab", Endpoint: "192.168.231.1:17444", Interface: "ccip0", Clients: map[string]string{s.AllowedClients[0]: "10.231.0.2"}, Destinations: []string{"10.232.0.1/32"}, Trust: s}
		ipClient := ipvpn.Config{Version: 2, Environment: "isolated-lab", Endpoint: ipServer.Endpoint, Interface: "ccip0", DeviceIP: "10.231.0.2", Destinations: ipServer.Destinations, Trust: c}
		for name, cfg := range map[string]ipvpn.Config{"ip-server.json": ipServer, "ip-client.json": ipClient} {
			b, e := json.MarshalIndent(cfg, "", "  ")
			if e != nil {
				return e
			}
			if e = os.WriteFile(filepath.Join(absolute, name), b, 0600); e != nil {
				return e
			}
		}
		fmt.Println("Disposable lab created. Certificates expire in 24 hours.")
		return nil
	}
	if mode == "ip-server" || mode == "ip-client" {
		return runIP(mode, path)
	}
	if mode == "http-lab" {
		if err := core.Loopback(path); err != nil {
			return err
		}
		return http.ListenAndServe(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "CONNECT lab HTTP OK\n") }))
	}
	if mode != "server" && mode != "client" {
		return fmt.Errorf("unknown command")
	}
	cfg, err := core.Load(path)
	if err != nil {
		return err
	}
	if err = core.Loopback(cfg.Listen); err != nil {
		return err
	}
	t, err := core.TLS(cfg, mode == "server")
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	fmt.Printf("CONNECT lab %s listening on %s\n", mode, listener.Addr())
	if mode == "server" {
		return core.Serve(ctx, listener, t, cfg.Services)
	}
	return core.Forward(ctx, listener, cfg.Server, cfg.Service, t)
}

func runIP(mode, path string) error {
	cfg, err := ipvpn.Load(path)
	if err != nil {
		return err
	}
	server := mode == "ip-server"
	policies, err := cfg.Validate(server)
	if err != nil {
		return err
	}
	t, err := ipvpn.TLS(cfg, server)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	stats := &ipvpn.Stats{}
	defer func() { b, _ := json.Marshal(stats.Snapshot()); fmt.Printf("CONNECT IP stats %s\n", b) }()
	if server {
		l, closeListener, e := ipvpn.Listen(cfg.Endpoint, t)
		if e != nil {
			return e
		}
		defer closeListener()
		d, e := ipvpn.Open(cfg.Interface)
		if e != nil {
			return e
		}
		defer d.Close()
		fmt.Printf("CONNECT IP server ready interface=%s mtu=%d\n", cfg.Interface, ipvpn.MTU)
		return ipvpn.Serve(ctx, l, d, policies, stats)
	}
	// Authenticate and validate address assignment before creating an interface.
	hctx, hcancel := context.WithTimeout(ctx, 10*time.Second)
	c, e := ipvpn.Dial(hctx, cfg.Endpoint, t, policies[""].Device)
	hcancel()
	if e != nil {
		return e
	}
	defer c.CloseWithError(0, "client stopped")
	d, e := ipvpn.Open(cfg.Interface)
	if e != nil {
		return e
	}
	defer d.Close()
	fmt.Printf("CONNECT IP client ready interface=%s address=%s mtu=%d\n", cfg.Interface, cfg.DeviceIP, ipvpn.MTU)
	return ipvpn.Client(ctx, c, d, policies[""], stats)
}
