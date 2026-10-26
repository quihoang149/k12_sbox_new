// Package chain is a small Ethereum-style blockchain simulator whose hash
// function is pluggable, so the same chain can run on Keccak-256 (Ethereum's
// choice) or on KangarooTwelve for comparison.
//
// Simplifications versus real Ethereum (state them in the thesis):
//   - account signatures use ECDSA P-256 from the Go standard library instead
//     of secp256k1, and the public key travels with the transaction instead of
//     being recovered from (v, r, s); validator signatures use ed25519
//     instead of BLS;
//   - the world state and transaction roots are binary Merkle trees, not
//     Merkle-Patricia tries;
//   - there is no EVM: transactions are value transfers with a flat gas cost;
//   - consensus is pluggable: PoW ("hash(sealHash || nonce) <= 2^256 /
//     difficulty" with difficulty adjustment, not Ethash) or a simplified
//     Gasper-like PoS (see pos.go).
//
// The encoding (RLP), address derivation (last 20 bytes of H(pubkey)) and
// header/transaction layout follow Ethereum closely.
package chain

import (
	"encoding/hex"
	"strings"
	"sync/atomic"
	"time"

	"k12chain/k12"
)

// Hash is a 32-byte digest.
type Hash [32]byte

func (h Hash) Hex() string   { return "0x" + hex.EncodeToString(h[:]) }
func (h Hash) Short() string { return hex.EncodeToString(h[:4]) }

// Address is a 20-byte account address.
type Address [20]byte

func (a Address) Hex() string { return "0x" + hex.EncodeToString(a[:]) }

// Hasher is the one place where the chain touches a hash function.
type Hasher interface {
	Name() string
	// Sum hashes the concatenation of parts.
	Sum(parts ...[]byte) Hash
}

// ---- KangarooTwelve ----

type K12Hasher struct {
	custom []byte
	// Workers > 1 hashes the 8 KiB chunks of long inputs (>= 40 KiB) on
	// that many goroutines, using K12's tree mode. 0 or 1 = sequential.
	Workers int
}

// NewK12Hasher returns a sequential K12 hasher. custom is K12's
// customization string; pass nil for plain K12.
func NewK12Hasher(custom []byte) *K12Hasher { return &K12Hasher{custom: custom} }

func (h *K12Hasher) Name() string {
	if h.Workers > 1 {
		return "K12-par"
	}
	return "K12"
}

func (h *K12Hasher) Sum(parts ...[]byte) Hash {
	if h.Workers > 1 && len(parts) == 1 && len(parts[0]) >= k12.ParallelThreshold {
		return k12.K12SumParallel(h.custom, parts[0], h.Workers)
	}
	return k12.K12SumParts(h.custom, parts...)
}

// ---- Keccak-256 (Ethereum) ----

type KeccakHasher struct{}

func NewKeccakHasher() KeccakHasher { return KeccakHasher{} }

func (KeccakHasher) Name() string { return "Keccak-256" }

// Keccak-256 has no parallel mode: a sponge absorbs its input strictly in
// sequence, each block depending on the previous one.

func (KeccakHasher) Sum(parts ...[]byte) Hash { return k12.KeccakSumParts(parts...) }

// ---- variants for the S-box experiment ----

// K12SBoxHasher is KangarooTwelve whose permutation uses the proposed
// S-box instead of chi (pure Go).
type K12SBoxHasher struct {
	custom  []byte
	Workers int // as K12Hasher.Workers
}

func NewK12SBoxHasher(custom []byte) *K12SBoxHasher { return &K12SBoxHasher{custom: custom} }

func (h *K12SBoxHasher) Name() string {
	if h.Workers > 1 {
		return "K12-SBox-par"
	}
	return "K12-SBox"
}

func (h *K12SBoxHasher) Sum(parts ...[]byte) Hash {
	if h.Workers > 1 && len(parts) == 1 && len(parts[0]) >= k12.ParallelThreshold {
		return k12.K12SBoxSumParallel(h.custom, parts[0], h.Workers)
	}
	return k12.K12SBoxSumParts(h.custom, parts...)
}

// K12GoHasher is standard K12 forced onto the pure-Go permutation.
type K12GoHasher struct{}

func (K12GoHasher) Name() string             { return "K12-Go" }
func (K12GoHasher) Sum(parts ...[]byte) Hash { return k12.K12GoSumParts(nil, parts...) }

// KeccakGoHasher is Keccak-256 forced onto the pure-Go permutation.
type KeccakGoHasher struct{}

func (KeccakGoHasher) Name() string             { return "Keccak-256-Go" }
func (KeccakGoHasher) Sum(parts ...[]byte) Hash { return k12.KeccakGoSumParts(parts...) }

// HasherNames lists the names accepted by HasherByName.
var HasherNames = []string{"keccak", "keccak-go", "k12", "k12-go", "k12sbox"}

// WithWorkers enables K12's parallel tree mode on hashers that support it
// (K12, K12-SBox) and returns h; other hashers are returned unchanged.
func WithWorkers(h Hasher, workers int) Hasher {
	switch v := h.(type) {
	case *K12Hasher:
		v.Workers = workers
	case *K12SBoxHasher:
		v.Workers = workers
	}
	return h
}

// HasherByName returns a hasher by short name (see HasherNames).
//
// "keccak" and "k12" use the amd64 assembly permutation where available;
// the "-go" variants and "k12sbox" always run pure Go. Compare k12sbox with
// keccak-go / k12-go for an implementation-neutral result.
func HasherByName(name string) (Hasher, bool) {
	switch strings.ToLower(name) {
	case "k12", "kangarootwelve":
		return NewK12Hasher(nil), true
	case "k12-go":
		return K12GoHasher{}, true
	case "k12sbox", "k12-sbox":
		return NewK12SBoxHasher(nil), true
	case "keccak", "keccak256", "keccak-256":
		return NewKeccakHasher(), true
	case "keccak-go", "keccak256-go":
		return KeccakGoHasher{}, true
	}
	return nil, false
}

// ---- instrumentation ----

// Counting wraps a Hasher and counts calls, input bytes and (optionally)
// time spent hashing. The time measurement adds two clock reads per call,
// so it slightly overstates the hashing share; it is the same overhead for
// both hash functions.
type Counting struct {
	Inner  Hasher
	Timing bool
	calls  atomic.Uint64
	bytes  atomic.Uint64
	nanos  atomic.Int64
}

func NewCounting(h Hasher) *Counting { return &Counting{Inner: h} }

func (c *Counting) Name() string { return c.Inner.Name() }

func (c *Counting) Sum(parts ...[]byte) Hash {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	c.calls.Add(1)
	c.bytes.Add(uint64(n))
	if !c.Timing {
		return c.Inner.Sum(parts...)
	}
	t0 := time.Now()
	out := c.Inner.Sum(parts...)
	c.nanos.Add(int64(time.Since(t0)))
	return out
}

// Stats returns (calls, bytes) since the last Reset.
func (c *Counting) Stats() (calls, bytes uint64) { return c.calls.Load(), c.bytes.Load() }

// HashTime is the time spent inside the hash function since the last Reset
// (only when Timing is on).
func (c *Counting) HashTime() time.Duration { return time.Duration(c.nanos.Load()) }

func (c *Counting) Reset() { c.calls.Store(0); c.bytes.Store(0); c.nanos.Store(0) }
