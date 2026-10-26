package chain

import (
	"runtime"
	"sync"
)

// Node-level parallelism, as in production clients:
//
//   - signatures of all transactions and attestations in a block are
//     verified concurrently before execution (go-ethereum's "sender
//     cacher" does the same for transactions);
//   - transactions are then executed sequentially, because each may depend
//     on the state left by the previous one;
//   - Merkle roots are hashed level by level, each level split across
//     cores (go-ethereum hashes the 16 sub-tries of the root in parallel).
//
// These apply to every hash function equally. K12's own tree-mode
// parallelism for long inputs is separate (see k12.K12SumParallel).

// DefaultWorkers is the number of CPU threads available to the process.
func DefaultWorkers() int { return runtime.GOMAXPROCS(0) }

// parallelFor runs f over [0, n) split into contiguous ranges, on up to
// workers goroutines. Below minPer items per worker it stays sequential.
func parallelFor(n, workers, minPer int, f func(lo, hi int)) {
	if workers > n/max(minPer, 1) {
		workers = n / max(minPer, 1)
	}
	if workers <= 1 {
		f(0, n)
		return
	}
	per := (n + workers - 1) / workers
	var wg sync.WaitGroup
	for lo := 0; lo < n; lo += per {
		hi := min(lo+per, n)
		wg.Add(1)
		go func() {
			defer wg.Done()
			f(lo, hi)
		}()
	}
	wg.Wait()
}

// merkleMinPerWorker: below this many hashes per goroutine, synchronisation
// costs more than it saves.
const merkleMinPerWorker = 256

// MerkleRootP is MerkleRoot computed with up to workers goroutines.
// The result is identical to MerkleRoot.
func MerkleRootP(h Hasher, leaves [][]byte, workers int) Hash {
	if workers <= 1 || len(leaves) < 2*merkleMinPerWorker {
		return MerkleRoot(h, leaves)
	}
	cur := make([]Hash, len(leaves))
	parallelFor(len(leaves), workers, merkleMinPerWorker, func(lo, hi int) {
		for i := lo; i < hi; i++ {
			cur[i] = h.Sum(leafPrefix, leaves[i])
		}
	})
	next := make([]Hash, (len(cur)+1)/2)
	for len(cur) > 1 {
		n := len(cur)
		m := (n + 1) / 2
		parallelFor(m, workers, merkleMinPerWorker, func(lo, hi int) {
			for j := lo; j < hi; j++ {
				if 2*j+1 == n {
					next[j] = cur[2*j] // odd node promoted
				} else {
					next[j] = h.Sum(nodePrefix, cur[2*j][:], cur[2*j+1][:])
				}
			}
		})
		cur, next = next[:m], cur[:(m+1)/2]
	}
	return cur[0]
}

// TxRootP is TxRoot with parallel hashing.
func TxRootP(h Hasher, txs []*Transaction, workers int) Hash {
	leaves := make([][]byte, len(txs))
	for i, tx := range txs {
		leaves[i] = tx.RLP()
	}
	return MerkleRootP(h, leaves, workers)
}

// RootP is the state root with parallel hashing.
func (s *StateDB) RootP(h Hasher, workers int) Hash { return MerkleRootP(h, s.leaves(), workers) }

type senderResult struct {
	from Address
	err  error
}

// recoverSenders verifies every transaction signature, in parallel.
func recoverSenders(h Hasher, txs []*Transaction, workers int) []senderResult {
	out := make([]senderResult, len(txs))
	parallelFor(len(txs), workers, 4, func(lo, hi int) {
		for i := lo; i < hi; i++ {
			out[i].from, out[i].err = txs[i].Sender(h)
		}
	})
	return out
}
