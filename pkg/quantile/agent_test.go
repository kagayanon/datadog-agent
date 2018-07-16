package quantile

import (
	"testing"
)

func TestAgent(t *testing.T) {
	a := &Agent{}

	type testcase struct {
		// expected
		// s.Basic.Cnt should equal binsum + buf
		binsum int // expected sum(b.n) for bin in a.
		buf    int // expected len(a.buf)

		// action
		ninsert int  // ninsert values are inserted before checking
		flush   bool // flush before checking
		reset   bool // reset befor checking
	}

	setup := func(t *testing.T, tt testcase) {
		for i := 0; i < tt.ninsert; i++ {
			a.Insert(float64(i))
		}

		if tt.reset {
			a.Reset()
		}

		if tt.flush {
			a.Flush()
		}
	}

	check := func(t *testing.T, exp testcase) {
		t.Helper()

		if l := len(a.Buf); l != exp.buf {
			t.Fatalf("len(a.buf) wrong. got:%d, want:%d", l, exp.buf)
		}

		binsum := 0
		for _, b := range a.Sketch.bins {
			binsum += int(b.n)
		}

		if got, want := binsum, exp.binsum; got != want {
			t.Fatalf("sum(b.n) wrong. got:%d, want:%d", got, want)
		}

		if got, want := a.Sketch.count, binsum; got != want {
			t.Fatalf("s.count should match binsum. got:%d, want:%d", got, want)
		}

		if got, want := int(a.Sketch.Basic.Cnt), exp.binsum+exp.buf; got != want {
			t.Fatalf("Summary.Cnt should equal len(buf)+s.count. got:%d, want: %d", got, want)
		}
	}

	// NOTE: these tests share the same sketch, so every test depends on the
	// previous test.
	for _, tt := range []testcase{
		{binsum: 0, buf: agentBufCap - 1, ninsert: agentBufCap - 1},
		{binsum: agentBufCap, buf: 0, ninsert: 1},
		{binsum: agentBufCap, buf: 1, ninsert: 1},
		{binsum: 2 * agentBufCap, buf: 1, ninsert: agentBufCap},
		{binsum: 2*agentBufCap + 1, buf: 0, flush: true},
		{reset: true},
		{flush: true},
	} {
		setup(t, tt)
		check(t, tt)
	}
}
