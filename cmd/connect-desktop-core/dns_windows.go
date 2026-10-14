//go:build windows

package main

import (
	"crypto/rand"
	"encoding/binary"
	"github.com/sanderstripa/connect-core/internal/desktop"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"net"
	"time"
)

func (w *worker) probeDNS(cfg ipvpn.Config, stats *ipvpn.Stats) {
	rtt := uint64(0)
	func() {
		// Source binding and WFP require this diagnostic to use the tunnel. No DNS
		// resolver, proxy, alternate server, TCP or direct-network fallback is used.
		sock, e := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(cfg.DeviceIP)}, &net.UDPAddr{IP: net.ParseIP(cfg.Network.DNS), Port: 53})
		if e != nil {
			return
		}
		defer sock.Close()
		sock.SetDeadline(time.Now().Add(3 * time.Second))
		query := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
		if _, e = rand.Read(query[:2]); e != nil {
			return
		}
		start := time.Now()
		if _, e = sock.Write(query); e != nil {
			return
		}
		reply := make([]byte, 512)
		n, e := sock.Read(reply)
		if e != nil || n < 12 || binary.BigEndian.Uint16(reply) != binary.BigEndian.Uint16(query) || reply[2]&0x80 == 0 || binary.BigEndian.Uint16(reply[4:]) != 1 {
			return
		}
		rtt = uint64(time.Since(start).Microseconds())
		if rtt == 0 {
			rtt = 1
		}
	}()
	w.mu.Lock()
	if w.stats == stats && w.state == desktop.Connected {
		w.dnsRTT = rtt
		if rtt == 0 {
			w.code = 8
		} else {
			w.code = 0
		}
	}
	w.mu.Unlock()
	w.emit()
}
