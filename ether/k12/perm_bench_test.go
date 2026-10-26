package k12

import "testing"

// BenchmarkPermutation measures one call of each permutation:
//
//	go test ./k12 -run '^$' -bench Permutation -count 5
//
// Keccak-256 uses 24 rounds, K12 and K12-SBox 12. "asm" is the amd64
// assembly (falls back to Go elsewhere); "go" is always pure Go.
func BenchmarkPermutation(b *testing.B) {
	var a [25]uint64
	cases := []struct {
		name string
		f    func(*[25]uint64, int)
		nr   int
	}{
		{"Keccak-f-24/asm", keccakF1600, 24},
		{"Keccak-f-24/go", keccakF1600Generic, 24},
		{"Keccak-p-12/asm", keccakF1600, 12},
		{"Keccak-p-12/go", keccakF1600Generic, 12},
		{"SBox-p-12/go", keccakF1600SBox, 12},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(200)
			for i := 0; i < b.N; i++ {
				c.f(&a, c.nr)
			}
		})
	}
}
