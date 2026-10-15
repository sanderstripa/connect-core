package ipvpn

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func TestActivatedSocketSurvivesDataServerRestart(t *testing.T) {
	if os.Getenv("CONNECT_ACTIVATION_TEST_CHILD") == "1" {
		os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
		os.Setenv("LISTEN_FDS", "1")
		address := os.Getenv("CONNECT_ACTIVATION_TEST_ADDRESS")
		first, err := activatedPacketConn(address)
		if err != nil {
			t.Fatal(err)
		}
		first.Close()
		if wrong, err := activatedPacketConn("127.0.0.1:1"); err == nil {
			wrong.Close()
			t.Fatal("wrong endpoint adopted")
		}
		second, err := activatedPacketConn(address)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close()
		second.SetDeadline(time.Now().Add(time.Second))
		if _, err = second.WriteTo([]byte("probe"), second.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		var p [16]byte
		n, _, err := second.ReadFrom(p[:])
		if err != nil || string(p[:n]) != "probe" {
			t.Fatalf("inherited socket lost: %v", err)
		}
		return
	}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	file, err := socket.File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestActivatedSocketSurvivesDataServerRestart$")
	command.ExtraFiles = []*os.File{file}
	command.Env = append(os.Environ(), "CONNECT_ACTIVATION_TEST_CHILD=1", "CONNECT_ACTIVATION_TEST_ADDRESS="+socket.LocalAddr().String())
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("socket restart: %v %s", err, out)
	}
}
