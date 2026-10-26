package chain

import (
	"bytes"
	"testing"
)

func TestAppendRLPMatches(t *testing.T) {
	for _, u := range []uint64{0, 1, 127, 128, 255, 256, 1 << 20, 1<<64 - 1} {
		if got := appendRLPUint(nil, u); !bytes.Equal(got, rlpUint(u)) {
			t.Errorf("uint %d: %x vs %x", u, got, rlpUint(u))
		}
	}
	for _, n := range []int{0, 1, 55, 56, 300} {
		b := bytes.Repeat([]byte{0x90}, n)
		if got := appendRLPBytes(nil, b); !bytes.Equal(got, rlpBytes(b)) {
			t.Errorf("bytes len %d differ", n)
		}
		if got := appendRLPList(nil, b); !bytes.Equal(got, rlpList(b)) {
			t.Errorf("list len %d differ", n)
		}
	}
}
