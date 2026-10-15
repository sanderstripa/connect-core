package ipvpn

import (
	"errors"
	"sync"
	"time"
)

// Control serializes packet authorization and session admission. Packets already
// admitted before a denial may finish their OS write; subsequent packets cannot.
// Persist a deny decision before calling Deny. A denied certificate cannot
// reconnect, including when its TLS handshake was already in flight.
type Control struct {
	mu       sync.Mutex
	policies map[string]Policy
	denied   map[string]bool
	sessions map[string]func()
	counters map[string]Usage
}
type Usage struct {
	Connected    bool      `json:"connected"`
	Received     uint64    `json:"received_bytes"`
	Sent         uint64    `json:"sent_bytes"`
	LastActivity time.Time `json:"last_activity"`
}

func NewControl(p map[string]Policy) *Control {
	return &Control{policies: p, denied: map[string]bool{}, sessions: map[string]func(){}, counters: map[string]Usage{}}
}
func (c *Control) Policy(pin string) (Policy, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.policies[pin]
	return p, ok && !c.denied[pin]
}
func (c *Control) Admit(pin string, close func()) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.policies[pin]; !ok || c.denied[pin] || c.sessions[pin] != nil {
		return false
	}
	c.sessions[pin] = close
	u := c.counters[pin]
	u.Connected = true
	u.LastActivity = time.Now().UTC()
	c.counters[pin] = u
	return true
}
func (c *Control) Release(pin string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, pin)
	u := c.counters[pin]
	u.Connected = false
	c.counters[pin] = u
}

func (c *Control) Busy(pin string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.denied[pin] && c.sessions[pin] != nil
}
func (c *Control) Deny(pin string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.denied[pin] = true
	if close := c.sessions[pin]; close != nil {
		close()
	}
}

// ReplacePolicy is used only with a validated complete configuration.
func (c *Control) Add(pin string, p Policy) { c.mu.Lock(); defer c.mu.Unlock(); c.policies[pin] = p }
func (c *Control) Transfer(pin string, incoming bool, size int, deliver func() error) error {
	c.mu.Lock()
	if c.denied[pin] || c.sessions[pin] == nil {
		c.mu.Unlock()
		return errors.New("access denied")
	}
	// Never hold the authorization mutex across a potentially blocked TUN write:
	// a stalled device must not prevent closing a revoked QUIC session.
	c.mu.Unlock()
	if err := deliver(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	u := c.counters[pin]
	if incoming {
		u.Received += uint64(size)
	} else {
		u.Sent += uint64(size)
	}
	u.LastActivity = time.Now().UTC()
	c.counters[pin] = u
	return nil
}
func (c *Control) Snapshot() map[string]Usage {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]Usage{}
	for k, v := range c.counters {
		out[k] = v
	}
	return out
}
