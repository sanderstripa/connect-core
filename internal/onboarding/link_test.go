package onboarding

import "testing"

func TestRejectInventedUnsafeOrDuplicateLinks(t *testing.T) {
	for _, s := range []string{"connect://anything", "connect://enroll?v=9", "connect://enroll?v=1&u=http://evil&t=abc&c=abc", "connect://enroll?v=1&v=1&u=https://evil&t=abc&c=abc", "http://127.0.0.1"} {
		if _, e := Parse(s); e == nil {
			t.Fatal("unsafe link accepted", s)
		}
	}
}
