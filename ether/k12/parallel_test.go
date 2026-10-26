package k12

import (
	"encoding/hex"
	"testing"
)

// The parallel implementation must reproduce the official K12 vectors.
func TestParallelOfficialVectors(t *testing.T) {
	for _, v := range vectors {
		if v.outputLen != 32 {
			continue
		}
		for _, w := range []int{1, 2, 3, 8, 0} {
			got := K12SumParallel(v.customString, v.message, w)
			if hex.EncodeToString(got[:]) != v.expectedOutput {
				t.Fatalf("len(M)=%d len(C)=%d workers=%d: got %x", len(v.message), len(v.customString), w, got)
			}
		}
	}
}

// ...and agree with the sequential tree code for both permutations, at chunk
// boundaries and when the customization string spills into extra chunks.
func TestParallelMatchesTree(t *testing.T) {
	sizes := []int{0, 1, 8190, 8191, 8192, 8193, 16383, 16384, 16385, 5*8192 - 3, 5 * 8192, 40000, 300000}
	customs := [][]byte{nil, []byte("ethereum"), pattern(8190), pattern(20000)}
	for _, custom := range customs {
		for _, n := range sizes {
			msg := pattern(n)
			for _, p := range []permKind{permKeccak, permSBox} {
				h := newK12(custom, p)
				h.Write(msg)
				var want [32]byte
				h.Read(want[:])
				for _, w := range []int{1, 2, 5, 16} {
					if got := k12SumParallel(p, custom, msg, w); got != want {
						t.Fatalf("perm=%d custom=%d n=%d workers=%d: mismatch", p, len(custom), n, w)
					}
				}
			}
		}
	}
}
