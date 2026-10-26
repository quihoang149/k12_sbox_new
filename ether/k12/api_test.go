package k12

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Known Ethereum Keccak-256 vectors.
func TestKeccak256Vectors(t *testing.T) {
	cases := map[string]string{
		"":    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
		// keccak256("transfer(address,uint256)") -> ERC-20 selector a9059cbb
		"transfer(address,uint256)": "a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b",
	}
	for in, want := range cases {
		got := KeccakSum256([]byte(in))
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("keccak256(%q) = %x, want %s", in, got, want)
		}
	}
	// Multi-block input must match streaming writes.
	long := pattern(1000)
	one := KeccakSum256(long)
	h := NewKeccak256()
	for i := 0; i < len(long); i += 7 {
		end := i + 7
		if end > len(long) {
			end = len(long)
		}
		h.Write(long[i:end])
	}
	if !bytes.Equal(h.Sum(nil), one[:]) {
		t.Fatal("streaming keccak256 differs from one-shot")
	}
}

func TestK12ResetAndClone(t *testing.T) {
	msg := pattern(20000) // several chunks, exercises tree mode
	want := Sum256(msg)

	h := NewK12(nil)
	h.Write(pattern(9000))
	var tmp [32]byte
	h.Read(tmp[:])
	h.Reset()
	h.Write(msg)
	var got [32]byte
	h.Read(got[:])
	if got != want {
		t.Fatalf("Reset: got %x want %x", got, want)
	}

	h2 := NewK12(nil)
	h2.Write(msg[:100])
	c := h2.Clone()
	h2.Write(msg[100:])
	c.Write(msg[100:])
	var a, b [32]byte
	h2.Read(a[:])
	c.Read(b[:])
	if a != want || b != want {
		t.Fatalf("Clone: %x / %x want %x", a, b, want)
	}
}

// The single-chunk fast path must agree with the tree implementation,
// including right at the 8192-byte boundary.
func TestK12SumPartsMatchesTree(t *testing.T) {
	for _, custom := range [][]byte{nil, []byte("eth"), pattern(300)} {
		for _, n := range []int{0, 1, 32, 167, 168, 169, 8000, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 20000} {
			msg := pattern(n)
			want := SumCustom256(custom, msg)
			if got := K12SumParts(custom, msg); got != want {
				t.Fatalf("custom=%d n=%d: fast path differs", len(custom), n)
			}
			if n > 2 {
				if got := K12SumParts(custom, msg[:n/3], msg[n/3:]); got != want {
					t.Fatalf("custom=%d n=%d: split parts differ", len(custom), n)
				}
			}
		}
	}
}
