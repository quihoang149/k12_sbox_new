package chain

import (
	"fmt"
	"testing"
)

// go test ./chain -bench . -benchmem
//
// Each benchmark runs once per hash function so results line up in pairs:
// BenchmarkHash/K12/1KiB vs BenchmarkHash/Keccak-256/1KiB, etc.

// benchHashers: Keccak-256 and K12 with assembly (amd64), the same two in
// pure Go, and K12-SBox (pure Go). Fair comparison: K12-SBox vs *-Go.
var benchHashers = []Hasher{NewKeccakHasher(), KeccakGoHasher{}, NewK12Hasher(nil), K12GoHasher{}, NewK12SBoxHasher(nil)}

var sizes = []int{32, 64, 136, 256, 1 << 10, 8 << 10, 64 << 10, 1 << 20}

func sizeName(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%dMiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%dKiB", n>>10)
	}
	return fmt.Sprintf("%dB", n)
}

func BenchmarkHash(b *testing.B) {
	for _, h := range benchHashers {
		for _, n := range sizes {
			data := make([]byte, n)
			b.Run(h.Name()+"/"+sizeName(n), func(b *testing.B) {
				b.SetBytes(int64(n))
				for i := 0; i < b.N; i++ {
					h.Sum(data)
				}
			})
		}
	}
}

func BenchmarkTxHash(b *testing.B) {
	k, _ := GenerateKey()
	for _, h := range benchHashers {
		tx := &Transaction{GasPrice: 1, GasLimit: 21000, Value: 1, ChainID: 1}
		tx.Sign(h, k)
		b.Run(h.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				tx.Hash(h)
			}
		})
	}
}

func BenchmarkMerkleRoot1000Tx(b *testing.B) {
	k, _ := GenerateKey()
	for _, h := range benchHashers {
		leaves := make([][]byte, 1000)
		for i := range leaves {
			tx := &Transaction{Nonce: uint64(i), GasPrice: 1, GasLimit: 21000, Value: 1, ChainID: 1}
			tx.Sign(h, k)
			leaves[i] = tx.RLP()
		}
		b.Run(h.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MerkleRoot(h, leaves)
			}
		})
	}
}

func BenchmarkPoWHash(b *testing.B) {
	for _, h := range benchHashers {
		var seal Hash
		b.Run(h.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				powHash(h, seal, uint64(i))
			}
		})
	}
}

// BenchmarkStateRoot measures the state root over n accounts: the most
// hash-intensive step of every block, for producers and validators alike.
func BenchmarkStateRoot(b *testing.B) {
	for _, h := range benchHashers {
		for _, n := range []int{1000, 10000, 100000} {
			st := NewStateDB()
			for i := 0; i < n; i++ {
				var a Address
				copy(a[:], u64(uint64(i)*2654435761))
				st.AddBalance(a, uint64(i))
			}
			st.Commit()
			b.Run(fmt.Sprintf("%s/%d", h.Name(), n), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					st.Root(h)
				}
			})
		}
	}
}

// BenchmarkPoSImport measures what a PoS validator node spends to verify
// and import one block (100 transfers, 32 validators attesting, 5000
// accounts). There is no puzzle: this is the whole per-block cost.
func BenchmarkPoSImport(b *testing.B) {
	for _, h := range benchHashers {
		n := newPoSNet(b, h, 5000, 32)
		nonces := make([]uint64, 5000)
		base := n.follower.Clone()
		blk, _, err := n.producer.ProduceBlock(n.transfers(h, 100, nonces), Address{})
		if err != nil {
			b.Fatal(err)
		}
		b.Run(h.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				c := base.Clone()
				b.StartTimer()
				if err := c.InsertBlock(blk); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkPoSProduce measures building + signing one PoS block.
func BenchmarkPoSProduce(b *testing.B) {
	for _, h := range benchHashers {
		n := newPoSNet(b, h, 5000, 32)
		nonces := make([]uint64, 5000)
		txs := n.transfers(h, 100, nonces)
		base := n.producer
		b.Run(h.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				c := base.Clone()
				b.StartTimer()
				if _, _, err := c.ProduceBlock(txs, Address{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkPoSImportStateSize shows how the benefit of a faster hash grows
// with the size of the state that every block commits to.
func BenchmarkPoSImportStateSize(b *testing.B) {
	for _, size := range []int{1000, 10000, 50000, 200000} {
		for _, h := range benchHashers {
			n := newPoSNetSized(b, h, 200, 32, size-200)
			nonces := make([]uint64, 200)
			base := n.follower.Clone()
			blk, _, err := n.producer.ProduceBlock(n.transfers(h, 100, nonces), Address{})
			if err != nil {
				b.Fatal(err)
			}
			b.Run(fmt.Sprintf("%s/%d", h.Name(), size), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					c := base.Clone()
					b.StartTimer()
					if err := c.InsertBlock(blk); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// ---- parallel (realistic) mode ----
//
//	go test ./chain -run '^$' -bench 'HashLarge|PoSImportParallel' -benchmem -count 5

// BenchmarkHashLarge compares long inputs, where K12's tree mode lets the
// 8 KiB chunks be hashed on all cores. Keccak-256 cannot do this.
func BenchmarkHashLarge(b *testing.B) {
	w := DefaultWorkers()
	hs := []Hasher{
		NewKeccakHasher(), KeccakGoHasher{},
		NewK12Hasher(nil), WithWorkers(NewK12Hasher(nil), w),
		NewK12SBoxHasher(nil), WithWorkers(NewK12SBoxHasher(nil), w),
	}
	for _, h := range hs {
		for _, n := range []int{64 << 10, 1 << 20, 16 << 20} {
			data := make([]byte, n)
			for i := range data {
				data[i] = byte(i)
			}
			b.Run(h.Name()+"/"+sizeName(n), func(b *testing.B) {
				b.SetBytes(int64(n))
				for i := 0; i < b.N; i++ {
					h.Sum(data)
				}
			})
		}
	}
}

// BenchmarkPoSImportParallel is BenchmarkPoSImportStateSize on a node that
// uses all cores for signatures and Merkle hashing, as real clients do.
func BenchmarkPoSImportParallel(b *testing.B) {
	hs := []Hasher{NewKeccakHasher(), KeccakGoHasher{}, NewK12Hasher(nil), NewK12SBoxHasher(nil)}
	for _, size := range []int{10000, 50000, 200000} {
		for _, h := range hs {
			n := newPoSNetSized(b, h, 200, 32, size-200)
			n.producer.Cfg.Workers = DefaultWorkers()
			nonces := make([]uint64, 200)
			base := n.follower.Clone()
			base.Cfg.Workers = DefaultWorkers()
			blk, _, err := n.producer.ProduceBlock(n.transfers(h, 100, nonces), Address{})
			if err != nil {
				b.Fatal(err)
			}
			b.Run(fmt.Sprintf("%s/%d", h.Name(), size), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					c := base.Clone()
					b.StartTimer()
					if err := c.InsertBlock(blk); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkHashHuge compares only Keccak-256 (pure Go, same implementation
// conditions as K12-SBox) with K12-SBox in parallel tree mode, over a wide
// range of input sizes:
//
//	go test ./chain -run '^$' -bench HashHuge -benchmem -count 5
func BenchmarkHashHuge(b *testing.B) {
	hs := []Hasher{KeccakGoHasher{}, WithWorkers(NewK12SBoxHasher(nil), DefaultWorkers())}
	for _, n := range []int{64 << 10, 256 << 10, 1 << 20, 4 << 20, 16 << 20, 64 << 20, 256 << 20} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i)
		}
		for _, h := range hs {
			b.Run(h.Name()+"/"+sizeName(n), func(b *testing.B) {
				b.SetBytes(int64(n))
				for i := 0; i < b.N; i++ {
					h.Sum(data)
				}
			})
		}
	}
}
