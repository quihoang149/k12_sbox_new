package k12

import (
	"math/bits"
	"math/rand"
	"testing"
)

// anfSBox evaluates the S-box exactly as written in the thesis (ANF of y0..y4).
func anfSBox(v int) int {
	x := func(i int) int { return (v >> i) & 1 }
	x0, x1, x2, x3, x4 := x(0), x(1), x(2), x(3), x(4)
	y0 := 1 ^ x0 ^ x1 ^ x0&x1 ^ x0&x2 ^ x2&x4 ^ x0&x2&x4 ^ x0&x3&x4
	y1 := 1 ^ x1 ^ x2 ^ x1&x2 ^ x0&x3 ^ x1&x3 ^ x0&x1&x3 ^ x0&x1&x4
	y2 := 1 ^ x2 ^ x3 ^ x2&x3 ^ x1&x4 ^ x2&x4 ^ x0&x1&x2 ^ x1&x2&x4
	y3 := 1 ^ x3 ^ x4 ^ x0&x2 ^ x0&x3 ^ x3&x4 ^ x0&x2&x3 ^ x1&x2&x3
	y4 := 1 ^ x0 ^ x4 ^ x1&x3 ^ x0&x4 ^ x1&x4 ^ x1&x3&x4 ^ x2&x3&x4
	return y0 | y1<<1 | y2<<2 | y3<<3 | y4<<4
}

// chiSBox is Keccak's chi as a 5-bit table: y_i = x_i ^ (~x_{i+1} & x_{i+2}).
func chiSBox(v int) int {
	out := 0
	for i := 0; i < 5; i++ {
		xi, x1, x2 := (v>>i)&1, (v>>((i+1)%5))&1, (v>>((i+2)%5))&1
		out |= (xi ^ ((1 ^ x1) & x2)) << i
	}
	return out
}

// cfeSBox is the closed-form expression (2.3).
func cfeSBox(v int) int {
	out := 0
	for i := 0; i < 5; i++ {
		x := func(k int) int { return (v >> ((i + k) % 5)) & 1 }
		y := 1 ^ x(0) ^ x(1) ^ x(0)&x(1) ^ x(0)&x(2) ^ x(2)&x(4) ^ x(0)&x(2)&x(4) ^ x(0)&x(3)&x(4)
		out |= y << i
	}
	return out
}

func TestSBoxDefinition(t *testing.T) {
	seen := map[int]bool{}
	for v := 0; v < 32; v++ {
		s := anfSBox(v)
		if s != cfeSBox(v) {
			t.Fatalf("ANF and closed form (2.3) differ at %d", v)
		}
		if s == v {
			t.Errorf("fixed point at %d", v)
		}
		seen[s] = true
	}
	if len(seen) != 32 {
		t.Fatal("S-box is not a bijection: Keccak-f would no longer be a permutation")
	}
	// Differential uniformity: max_{a!=0,b} #{x : S(x)^S(x^a) = b}.
	du := 0
	for a := 1; a < 32; a++ {
		var cnt [32]int
		for x := 0; x < 32; x++ {
			cnt[anfSBox(x)^anfSBox(x^a)]++
		}
		for _, c := range cnt {
			du = max(du, c)
		}
	}
	if du != 4 {
		t.Errorf("differential uniformity = %d, expected 4", du)
	}
}

var rhoOffsets = [25]int{0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14}

// refPermutation is a straightforward, spec-style Keccak-p[1600, nr] with a
// table-driven 5-bit S-box in place of chi. Slow but obviously correct.
func refPermutation(a *[25]uint64, nr int, sbox func(int) int) {
	var table [32]int
	for v := range table {
		table[v] = sbox(v)
	}
	for r := 24 - nr; r < 24; r++ {
		// theta
		var c [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d := c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
			for y := 0; y < 5; y++ {
				a[x+5*y] ^= d
			}
		}
		// rho + pi: B[y, 2x+3y] = rot(A[x,y], r[x,y])
		var b [25]uint64
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				b[y+5*((2*x+3*y)%5)] = bits.RotateLeft64(a[x+5*y], rhoOffsets[x+5*y])
			}
		}
		// non-linear layer: the S-box on every row, bit position by bit position
		for y := 0; y < 5; y++ {
			var out [5]uint64
			for j := 0; j < 64; j++ {
				v := 0
				for x := 0; x < 5; x++ {
					v |= int((b[x+5*y]>>j)&1) << x
				}
				s := table[v]
				for x := 0; x < 5; x++ {
					out[x] |= uint64((s>>x)&1) << j
				}
			}
			copy(a[5*y:5*y+5], out[:])
		}
		// iota
		a[0] ^= rc[r]
	}
}

func TestPermutationsMatchReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for trial := 0; trial < 20; trial++ {
		var st [25]uint64
		for i := range st {
			st[i] = rng.Uint64()
		}
		for _, nr := range []int{4, 12, 24} {
			// The reference with chi must reproduce Keccak-f: validates the reference.
			ref, got := st, st
			refPermutation(&ref, nr, chiSBox)
			keccakF1600Generic(&got, nr)
			if ref != got {
				t.Fatalf("reference (chi) != keccakF1600Generic, nr=%d", nr)
			}
			asm := st
			keccakF1600(&asm, nr) // the amd64 assembly only supports 12 or 24 rounds
			if (nr == 12 || nr == 24) && asm != got {
				t.Fatalf("assembly != generic, nr=%d", nr)
			}
			// Same reference with the new S-box must match the generated code.
			ref, got = st, st
			refPermutation(&ref, nr, anfSBox)
			keccakF1600SBox(&got, nr)
			if ref != got {
				t.Fatalf("reference (new S-box) != keccakF1600SBox, nr=%d", nr)
			}
		}
	}
}

func TestK12SBoxModes(t *testing.T) {
	for _, custom := range [][]byte{nil, []byte("eth")} {
		for _, n := range []int{0, 1, 32, 168, 8191, 8192, 8193, 20000, 100000} {
			msg := pattern(n)
			h := NewK12SBox(custom)
			h.Write(msg)
			var tree [32]byte
			h.Read(tree[:])
			if K12SBoxSumParts(custom, msg) != tree {
				t.Fatalf("custom=%d n=%d: fast path != tree mode", len(custom), n)
			}
			if K12SumParts(custom, msg) == tree {
				t.Fatalf("K12-SBox equals standard K12 at n=%d", n)
			}
			if K12GoSumParts(custom, msg) != K12SumParts(custom, msg) {
				t.Fatalf("K12 pure Go != K12 at n=%d", n)
			}
		}
	}
	for _, n := range []int{0, 135, 136, 137, 5000} {
		msg := pattern(n)
		if KeccakGoSumParts(msg) != KeccakSum256(msg) {
			t.Fatalf("Keccak pure Go != Keccak at n=%d", n)
		}
	}
}
