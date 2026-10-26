package chain

// Benchmarks behind the thesis tables. Run them with scripts/run_thesis_bench.ps1,
// which repeats every benchmark in separate `go test` invocations, then
// summarise with scripts/benchsummary.py.
//
// Measurement choices:
//   - The order of the hash functions is shuffled on every invocation, so a
//     laptop that throttles as it heats up does not always penalise the
//     hash function that happens to run last.
//   - T34* hash data that is already encoded: they measure hashing (plus Merkle
//     bookkeeping), not RLP encoding or state traversal.
//   - T35* force a garbage collection while the timer is stopped, so the GC
//     work caused by cloning a large state does not land in the timed import.
//   - T36-T38 put K12 in its most favourable setting: one long message
//     hashed in tree mode on all cores (Keccak-256 has no parallel mode).

import (
	"fmt"
	"math/rand"
	"runtime"
	"testing"
	"time"
)

var thesisRng = rand.New(rand.NewSource(time.Now().UnixNano()))

func shuffledHashers(hs ...Hasher) []Hasher {
	out := append([]Hasher(nil), hs...)
	thesisRng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// Fresh values every call: WithWorkers mutates K12 hashers.
func seqHashers() []Hasher {
	return []Hasher{NewKeccakHasher(), KeccakGoHasher{}, NewK12Hasher(nil), K12GoHasher{}, NewK12SBoxHasher(nil)}
}

func parHashers() []Hasher {
	w := DefaultWorkers()
	return []Hasher{
		NewKeccakHasher(), KeccakGoHasher{},
		NewK12SBoxHasher(nil),                 // sequential: gain from rate 168 vs 136 bytes
		WithWorkers(NewK12SBoxHasher(nil), w), // tree mode on all cores
		WithWorkers(NewK12Hasher(nil), w),     // standard K12, for reference
	}
}

func benchBlob(b *testing.B, label string, data []byte, hs []Hasher) {
	for _, h := range shuffledHashers(hs...) {
		b.Run(h.Name()+"/"+label, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				h.Sum(data)
			}
		})
	}
}

// ---------------- Table 3.4: hashing in transaction operations ----------------

// T34TxHash: hash of one RLP-encoded transfer (~163 bytes: 2 Keccak-256
// blocks, 1 K12 block).
func BenchmarkT34TxHash(b *testing.B) {
	k, _ := GenerateKey()
	tx := &Transaction{GasPrice: 1, GasLimit: 21000, Value: 1, ChainID: 1}
	tx.Sign(NewKeccakHasher(), k) // signature bytes only fill the encoding
	enc := tx.RLP()
	benchBlob(b, fmt.Sprintf("%dB", len(enc)), enc, seqHashers())
}

// T34Address: address derivation H(pubkey), 64 bytes (1 block for both).
func BenchmarkT34Address(b *testing.B) {
	k, _ := GenerateKey()
	benchBlob(b, "64B", k.PubBytes(), seqHashers())
}

// T34MerkleTx: Merkle root of 1000 encoded transactions.
func BenchmarkT34MerkleTx(b *testing.B) {
	k, _ := GenerateKey()
	leaves := make([][]byte, 1000)
	for i := range leaves {
		tx := &Transaction{Nonce: uint64(i), GasPrice: 1, GasLimit: 21000, Value: 1, ChainID: 1}
		tx.Sign(NewKeccakHasher(), k)
		leaves[i] = tx.RLP()
	}
	for _, h := range shuffledHashers(seqHashers()...) {
		b.Run(h.Name()+"/1000", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				MerkleRoot(h, leaves)
			}
		})
	}
}

// T34StateRoot: Merkle root over n already-encoded accounts.
func BenchmarkT34StateRoot(b *testing.B) {
	for _, n := range []int{1000, 10000, 100000} {
		st := NewStateDB()
		for i := 0; i < n; i++ {
			var a Address
			copy(a[:], u64(uint64(i)*2654435761))
			st.AddBalance(a, uint64(i))
		}
		st.Commit()
		leaves := st.leaves()
		for _, h := range shuffledHashers(seqHashers()...) {
			b.Run(fmt.Sprintf("%s/%d", h.Name(), n), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					MerkleRoot(h, leaves)
				}
			})
		}
	}
}

// ---------------- Table 3.5: validating and importing a PoS block ----------------

type importCase struct {
	base *Blockchain
	blk  *Block
}

func newImportCase(b *testing.B, h Hasher, size int) importCase {
	n := newPoSNetSized(b, h, 200, 32, size-200)
	nonces := make([]uint64, 200)
	base := n.follower.Clone()
	blk, _, err := n.producer.ProduceBlock(n.transfers(h, 100, nonces), Address{})
	if err != nil {
		b.Fatal(err)
	}
	return importCase{base, blk}
}

// T35Import: wall time of InsertBlock (100 transfers, 32 attestations) on a
// sequential node, for growing state sizes.
func BenchmarkT35Import(b *testing.B) {
	for _, size := range []int{1000, 10000, 50000, 200000} {
		for _, h := range shuffledHashers(seqHashers()...) {
			c := newImportCase(b, h, size)
			b.Run(fmt.Sprintf("%s/%d", h.Name(), size), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					bc := c.base.Clone()
					runtime.GC()
					b.StartTimer()
					if err := bc.InsertBlock(c.blk); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// T35HashShare: same import, reporting only the time spent inside the hash
// function (hash-ns/op) and the number of hash calls (hashes/op, which must
// be identical for every hash function). Its ns/op includes the timing
// overhead and is not meant to be reported.
func BenchmarkT35HashShare(b *testing.B) {
	for _, size := range []int{1000, 10000, 50000, 200000} {
		for _, inner := range shuffledHashers(seqHashers()...) {
			cnt := &Counting{Inner: inner}
			c := newImportCase(b, cnt, size)
			b.Run(fmt.Sprintf("%s/%d", inner.Name(), size), func(b *testing.B) {
				var hashNs int64
				var calls uint64
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					bc := c.base.Clone()
					runtime.GC()
					cnt.Reset()
					cnt.Timing = true
					b.StartTimer()
					if err := bc.InsertBlock(c.blk); err != nil {
						b.Fatal(err)
					}
					b.StopTimer()
					cnt.Timing = false
					hashNs += int64(cnt.HashTime())
					k, _ := cnt.Stats()
					calls += k
					b.StartTimer()
				}
				b.ReportMetric(float64(hashNs)/float64(b.N), "hash-ns/op")
				b.ReportMetric(float64(calls)/float64(b.N), "hashes/op")
			})
		}
	}
}

// ---------------- K12 in its most favourable setting ----------------

// T36Large: one long message, 64 KiB .. 256 MiB.
func BenchmarkT36Large(b *testing.B) {
	for _, n := range []int{64 << 10, 256 << 10, 1 << 20, 4 << 20, 16 << 20, 64 << 20, 256 << 20} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i)
		}
		benchBlob(b, sizeName(n), data, parHashers())
	}
}

// T36Scaling: K12-SBox tree mode on 64 MiB with 1..16 goroutines.
func BenchmarkT36Scaling(b *testing.B) {
	const n = 64 << 20
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i)
	}
	ws := []int{1, 2, 4, 8, 16}
	thesisRng.Shuffle(len(ws), func(i, j int) { ws[i], ws[j] = ws[j], ws[i] })
	for _, w := range ws {
		h := WithWorkers(NewK12SBoxHasher(nil), w)
		b.Run(fmt.Sprintf("K12-SBox-w%02d/%s", w, sizeName(n)), func(b *testing.B) {
			b.SetBytes(n)
			for i := 0; i < b.N; i++ {
				h.Sum(data)
			}
		})
	}
}

// T37Snapshot (proposed use): hash the whole serialised state as one message,
// e.g. to check a state snapshot during checkpoint sync. Not what Ethereum
// does today (it commits to a Merkle-Patricia trie).
func BenchmarkT37Snapshot(b *testing.B) {
	for _, n := range []int{10000, 50000, 200000} {
		st := NewStateDB()
		for i := 0; i < n; i++ {
			var a Address
			copy(a[:], u64(uint64(i)*2654435761))
			st.AddBalance(a, uint64(i))
		}
		st.Commit()
		var blob []byte
		for _, l := range st.leaves() {
			blob = append(blob, l...)
		}
		benchBlob(b, fmt.Sprintf("%dacc", n), blob, parHashers())
	}
}

// T38BlockBody (proposed use): hash the concatenated encoding of all
// transactions of a block as one message. 1500 transfers is about a full
// 30M-gas block of plain transfers.
func BenchmarkT38BlockBody(b *testing.B) {
	k, _ := GenerateKey()
	for _, ntx := range []int{100, 500, 1500} {
		var body []byte
		for i := 0; i < ntx; i++ {
			tx := &Transaction{Nonce: uint64(i), GasPrice: 1, GasLimit: 21000, Value: 1, ChainID: 1}
			tx.Sign(NewKeccakHasher(), k)
			body = append(body, tx.RLP()...)
		}
		benchBlob(b, fmt.Sprintf("%dtx", ntx), body, parHashers())
	}
}
