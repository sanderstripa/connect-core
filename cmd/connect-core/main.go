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

	"github.com/sanderstripa/connect-core/internal/core"
	"github.com/sanderstripa/connect-core/internal/lab"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: connect-core {init-lab|server|client|http-lab} {directory|config.json|127.0.0.1:port}")
	}
	mode, path := os.Args[1], os.Args[2]
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
		fmt.Println("Disposable lab created. Certificates expire in 24 hours.")
		return nil
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
