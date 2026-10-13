package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/sanderstripa/connect-core/internal/ipvpn"
)

// IPC v1 uses private inherited stdin/stdout handles, not a public TCP port.
// Commands are bounded JSON lines: status or stop. EOF means owner disappeared.
func runManaged(path string, ipc bool) error {
	cfg, e := ipvpn.Load(path)
	if e != nil {
		return e
	}
	if _, e = cfg.Validate(false); e != nil {
		return e
	}
	t, e := ipvpn.TLS(cfg, false)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	stats := &ipvpn.Stats{}
	var mu sync.Mutex
	last := ipvpn.Event{Version: 1, State: "starting", Interface: cfg.Interface}
	output := json.NewEncoder(os.Stdout)
	emit := func(ev ipvpn.Event) {
		mu.Lock()
		defer mu.Unlock()
		last = ev
		if ipc {
			if output.Encode(ev) != nil {
				cancel()
			}
		} else {
			fmt.Printf("CONNECT IP state=%s interface=%s\n", ev.State, ev.Interface)
		}
	}
	commands := make(chan error, 1)
	if ipc {
		go func() {
			s := bufio.NewScanner(os.Stdin)
			s.Buffer(make([]byte, 4096), 4096)
			for s.Scan() {
				var command struct {
					Version int    `json:"ipc_version"`
					Command string `json:"command"`
				}
				dec := json.NewDecoder(strings.NewReader(s.Text()))
				dec.DisallowUnknownFields()
				if dec.Decode(&command) != nil || command.Version != 1 || dec.Decode(new(any)) != io.EOF {
					commands <- errors.New("invalid IPC command")
					cancel()
					return
				}
				switch command.Command {
				case "stop":
					cancel()
					commands <- nil
					return
				case "status":
					mu.Lock()
					ev := last
					ev.Stats = stats.Snapshot()
					if output.Encode(ev) != nil {
						cancel()
					}
					mu.Unlock()
				default:
					commands <- errors.New("unsupported IPC command")
					cancel()
					return
				}
			}
			commands <- s.Err()
			cancel()
		}()
	}
	e = ipvpn.Managed(ctx, cfg, t, ipvpn.Open, stats, emit)
	select {
	case ce := <-commands:
		if ce != nil {
			return ce
		}
	default:
	}
	return e
}
