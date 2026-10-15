package ipvpn

import "sync/atomic"

var activatedReceiveBuffer, activatedSendBuffer atomic.Int64

func SocketBufferStats() map[string]int64 {
	return map[string]int64{"receive_bytes": activatedReceiveBuffer.Load(), "send_bytes": activatedSendBuffer.Load()}
}
