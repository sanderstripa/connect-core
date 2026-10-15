package desktop

import (
	"bytes"
	"os"
	"testing"
)

// Real Windows/Unix pipe throughput, without routes, TUN or network changes.
func BenchmarkPacketPipe(b *testing.B) {
	r, w, err := os.Pipe()
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	done := make(chan error, 1)
	go func() {
		for {
			kind, p, err := Read(r)
			if err != nil {
				done <- err
				return
			}
			if kind != ToTUN || len(p) != 1100 {
				done <- os.ErrInvalid
				return
			}
		}
	}()
	p := make([]byte, 1100)
	b.SetBytes(int64(len(p)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err = Write(w, ToTUN, p); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	w.Close()
	<-done
}

func TestFrames(t *testing.T) {
	var b bytes.Buffer
	if e := Write(&b, Import, []byte("configuration")); e != nil {
		t.Fatal(e)
	}
	kind, p, e := Read(&b)
	if e != nil || kind != Import || string(p) != "configuration" {
		t.Fatal("round trip")
	}
	for _, v := range [][]byte{{'C', 'C', Version + 1, 1, 0, 0, 0, 0}, {'C', 'C', 1, 1, 255, 255, 255, 255}, {'C', 'C', 1, 1, 1, 0, 0, 0}} {
		if _, _, e := Read(bytes.NewReader(v)); e == nil {
			t.Fatal("accepted invalid frame")
		}
	}
	if Write(&b, Import, make([]byte, MaxPayload+1)) == nil {
		t.Fatal("unbounded payload")
	}
}
