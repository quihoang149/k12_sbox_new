package chain

import (
	"fmt"
	"testing"
)

func TestMerkleRootParallelMatches(t *testing.T) {
	for _, h := range hashers {
		for _, n := range []int{0, 1, 2, 511, 512, 513, 1000, 1023, 1024, 1025, 4097, 20001} {
			leaves := make([][]byte, n)
			for i := range leaves {
				leaves[i] = []byte(fmt.Sprintf("leaf-%d", i))
			}
			want := MerkleRoot(h, leaves)
			for _, w := range []int{1, 2, 3, 8, 16} {
				if got := MerkleRootP(h, leaves, w); got != want {
					t.Fatalf("%s n=%d workers=%d: parallel root differs", h.Name(), n, w)
				}
			}
		}
	}
}

// A node using all cores and a strictly sequential node must agree on every
// block, including PoS signatures checked in parallel.
func TestParallelAndSequentialNodesAgree(t *testing.T) {
	for _, h := range hashers {
		n := newPoSNetSized(t, h, 50, 16, 3000)
		n.producer.Cfg.Workers = 8
		n.follower.Cfg.Workers = 1
		nonces := make([]uint64, 50)
		for i := 0; i < 4; i++ {
			blk, _, err := n.producer.ProduceBlock(n.transfers(h, 60, nonces), Address{})
			if err != nil {
				t.Fatal(err)
			}
			if err := n.follower.InsertBlock(blk); err != nil {
				t.Fatalf("%s: sequential node rejected parallel block: %v", h.Name(), err)
			}
		}
		if n.producer.State().Root(h) != n.follower.State().Root(h) {
			t.Fatal("states diverged")
		}
		// And the other way round: a bad signature must still be caught in parallel mode.
		par := n.follower.Clone()
		par.Cfg.Workers = 8
		blk, _, _ := n.producer.ProduceBlock(n.transfers(h, 60, nonces), Address{})
		blk.Txs[37].S[5] ^= 1
		blk.Header.TxRoot = TxRoot(h, blk.Txs)
		if err := par.InsertBlock(blk); err == nil {
			t.Fatal("parallel node accepted a bad transaction signature")
		}
	}
}

func TestK12HasherParallelTreeMode(t *testing.T) {
	data := make([]byte, 1<<20)
	for i := range data {
		data[i] = byte(i * 7)
	}
	for _, mk := range []func() Hasher{
		func() Hasher { return NewK12Hasher(nil) },
		func() Hasher { return NewK12SBoxHasher(nil) },
	} {
		seq := mk()
		par := WithWorkers(mk(), 8)
		if seq.Sum(data) != par.Sum(data) {
			t.Fatalf("%s: parallel tree mode changed the digest", par.Name())
		}
	}
}
