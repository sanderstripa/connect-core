package desktop

import (
	"bytes"
	"testing"
)

func TestFrames(t *testing.T) {
	var b bytes.Buffer
	if e := Write(&b, Import, []byte("configuration")); e != nil {
		t.Fatal(e)
	}
	kind, p, e := Read(&b)
	if e != nil || kind != Import || string(p) != "configuration" {
		t.Fatal("round trip")
	}
	for _, v := range [][]byte{{'C', 'C', 2, 1, 0, 0, 0, 0}, {'C', 'C', 1, 1, 255, 255, 255, 255}, {'C', 'C', 1, 1, 1, 0, 0, 0}} {
		if _, _, e := Read(bytes.NewReader(v)); e == nil {
			t.Fatal("accepted invalid frame")
		}
	}
	if Write(&b, Import, make([]byte, MaxPayload+1)) == nil {
		t.Fatal("unbounded payload")
	}
}
