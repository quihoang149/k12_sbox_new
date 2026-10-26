package k12

// This file adds a small, uniform API on top of the original K12 code and a
// legacy Keccak-256 (the variant Ethereum uses) built on the very same sponge
// and Keccak-f[1600] permutation. Sharing the permutation makes benchmarks
// between the two a fair comparison: the only differences are the number of
// rounds (12 vs 24), the rate (168 vs 136 bytes) and K12's tree mode.

// Sum256 returns the 32-byte KangarooTwelve digest of data with an empty
// customization string.
func Sum256(data []byte) (out [32]byte) {
	h := NewK12(nil)
	h.Write(data)
	h.Read(out[:])
	return
}

// SumCustom256 returns the 32-byte KangarooTwelve digest of data under the
// given customization string (used for domain separation).
func SumCustom256(custom, data []byte) (out [32]byte) {
	h := NewK12(custom)
	h.Write(data)
	h.Read(out[:])
	return
}

// Keccak256 is the original Keccak-256 (padding byte 0x01), as used by
// Ethereum. It is NOT the same as NIST SHA3-256 (padding byte 0x06).
type Keccak256 struct{ s state }

// NewKeccak256 creates a Keccak-256 hasher: rate 136 bytes, 24 rounds.
func NewKeccak256() *Keccak256 {
	return &Keccak256{s: state{rate: 136, dsbyte: 0x01, rounds: 24}}
}

func (k *Keccak256) Write(p []byte) (int, error) { return k.s.Write(p) }

// Sum returns the digest without changing the hasher's state.
func (k *Keccak256) Sum(in []byte) []byte {
	dup := k.s // value copy is a full clone
	var out [32]byte
	dup.Read(out[:])
	return append(in, out[:]...)
}

func (k *Keccak256) Reset() { k.s.Reset() }

// KeccakSum256 returns the Keccak-256 digest of data.
func KeccakSum256(data []byte) (out [32]byte) {
	s := state{rate: 136, dsbyte: 0x01, rounds: 24}
	s.Write(data)
	s.Read(out[:])
	return
}

// K12SumParts hashes the concatenation of parts with K12 (32-byte output)
// without heap allocation.
func K12SumParts(custom []byte, parts ...[]byte) [32]byte {
	return k12SumParts(permKeccak, custom, parts)
}

// K12GoSumParts is K12SumParts using the pure-Go permutation even where
// assembly exists, for apples-to-apples comparison with K12SBoxSumParts.
func K12GoSumParts(custom []byte, parts ...[]byte) [32]byte {
	return k12SumParts(permKeccakGo, custom, parts)
}

// K12SBoxSumParts is K12 with the proposed S-box in place of chi.
func K12SBoxSumParts(custom []byte, parts ...[]byte) [32]byte {
	return k12SumParts(permSBox, custom, parts)
}

func k12SumParts(p permKind, custom []byte, parts [][]byte) (out [32]byte) {
	// Fast path: when message || custom || right_encode(len(custom)) fits in
	// one 8192-byte chunk, K12 is a single TurboSHAKE128 call with domain
	// byte 0x07 (no tree). This skips the tree bookkeeping, which otherwise
	// costs ~1/3 of the time for short inputs such as Merkle nodes.
	total := len(custom) + len(right_encode(uint64(len(custom))))
	for _, b := range parts {
		total += len(b)
	}
	if total <= maxChunk {
		s := state{rate: 168, dsbyte: 0x07, perm: p}
		for _, b := range parts {
			s.Write(b)
		}
		s.Write(custom)
		s.Write(right_encode(uint64(len(custom))))
		s.Read(out[:])
		return
	}
	h := newK12(custom, p)
	for _, b := range parts {
		h.Write(b)
	}
	h.Read(out[:])
	return
}

// KeccakSumParts hashes the concatenation of parts with Keccak-256 without
// heap allocation.
func KeccakSumParts(parts ...[]byte) [32]byte { return keccakSumParts(permKeccak, parts) }

// KeccakGoSumParts is KeccakSumParts using the pure-Go permutation.
func KeccakGoSumParts(parts ...[]byte) [32]byte { return keccakSumParts(permKeccakGo, parts) }

func keccakSumParts(p permKind, parts [][]byte) (out [32]byte) {
	s := state{rate: 136, dsbyte: 0x01, rounds: 24, perm: p}
	for _, b := range parts {
		s.Write(b)
	}
	s.Read(out[:])
	return
}
