package ipvpn

import (
	"crypto/tls"
	"github.com/apernet/quic-go"
	"sort"
	"time"
)

type TransportSample struct {
	Cipher          string    `json:"tls_cipher"`
	Session         uint64    `json:"session"`
	Connected       bool      `json:"connected"`
	At              time.Time `json:"at"`
	RTTUS           int64     `json:"rtt_us"`
	LatestRTTUS     int64     `json:"latest_rtt_us"`
	PacketsSent     uint64    `json:"packets_sent"`
	PacketsReceived uint64    `json:"packets_received"`
	PacketsLost     uint64    `json:"packets_lost"`
	BytesSent       uint64    `json:"bytes_sent"`
	BytesReceived   uint64    `json:"bytes_received"`
}
type transportRecord struct {
	conn   *quic.Conn
	sample TransportSample
}

func readTransport(conn *quic.Conn, session uint64) TransportSample {
	s := conn.ConnectionStats()
	return TransportSample{Cipher: tls.CipherSuiteName(conn.ConnectionState().TLS.CipherSuite), Session: session, Connected: conn.Context().Err() == nil, At: time.Now().UTC(), RTTUS: s.SmoothedRTT.Microseconds(), LatestRTTUS: s.LatestRTT.Microseconds(), PacketsSent: s.PacketsSent, PacketsReceived: s.PacketsReceived, PacketsLost: s.PacketsLost, BytesSent: s.BytesSent, BytesReceived: s.BytesReceived}
}

func (c *Control) attachTransport(pin string, conn *quic.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sessions[pin] == nil {
		return
	}
	// Keep at most 32 records, matching the server's maximum admitted sessions.
	if _, exists := c.transports[pin]; !exists && len(c.transports) >= 32 {
		oldest := ""
		var serial uint64 = ^uint64(0)
		for key, r := range c.transports {
			if r.conn == nil && r.sample.Session < serial {
				oldest, serial = key, r.sample.Session
			}
		}
		if oldest == "" {
			return
		}
		delete(c.transports, oldest)
	}
	c.nextTransport++
	c.transports[pin] = transportRecord{conn: conn, sample: TransportSample{Session: c.nextTransport}}
}

// Export no addresses, names, certificate fingerprints or payloads.
func (c *Control) TransportSnapshot() []TransportSample {
	c.mu.Lock()
	records := make([]transportRecord, 0, len(c.transports))
	for _, r := range c.transports {
		records = append(records, r)
	}
	c.mu.Unlock()
	out := make([]TransportSample, 0, len(records))
	for _, r := range records {
		if r.conn != nil {
			r.sample = readTransport(r.conn, r.sample.Session)
		}
		out = append(out, r.sample)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Session < out[j].Session })
	return out
}
