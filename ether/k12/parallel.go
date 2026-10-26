package k12

import (
	"runtime"
	"sync"
)

// Parallel tree hashing.
//
// KangarooTwelve (RFC 9861) splits S = M || C || length_encode(|C|) into
// 8192-byte chunks S_0, S_1, ..., S_{n-1}. If n > 1:
//
//	CV_i       = TurboSHAKE128(S_i, D=0x0B, 32 bytes)       for i = 1..n-1
//	FinalNode  = S_0 || 0x03 0x00^7 || CV_1 || ... || CV_{n-1}
//	             || length_encode(n-1) || 0xFF 0xFF
//	output     = TurboSHAKE128(FinalNode, D=0x06)
//
// The CV_i are independent of each other, so they can be computed at the
// same time. Optimised implementations (XKCP) do it with SIMD, 2-8 chunks
// per instruction stream; here we use goroutines across CPU cores. Keccak-256
// is a single sequential sponge and has no equivalent.
//
// The result is bit-for-bit identical to the sequential tree implementation
// (tested against the official K12 vectors).

// ParallelMinChunks is the smallest number of chunks for which spawning
// goroutines pays off (below it the sequential path is used).
const ParallelMinChunks = 4

// ParallelThreshold is the input size (bytes) from which callers should
// prefer K12SumParallel over the sequential functions.
const ParallelThreshold = (ParallelMinChunks + 1) * maxChunk

// K12SumParallel is K12 with a 32-byte output, hashing chunks on up to
// workers goroutines (workers <= 0 means runtime.GOMAXPROCS(0)).
func K12SumParallel(custom, msg []byte, workers int) [32]byte {
	return k12SumParallel(permKeccak, custom, msg, workers)
}

// K12SBoxSumParallel is K12-SBox with parallel chunk hashing.
func K12SBoxSumParallel(custom, msg []byte, workers int) [32]byte {
	return k12SumParallel(permSBox, custom, msg, workers)
}

// virtualS describes S = msg || tail without copying msg.
type virtualS struct {
	msg, tail []byte
}

func (v *virtualS) len() int { return len(v.msg) + len(v.tail) }

// write absorbs S[start:end] into s.
func (v *virtualS) write(s *state, start, end int) {
	lm := len(v.msg)
	if start < lm {
		s.Write(v.msg[start:min(end, lm)])
	}
	if end > lm {
		s.Write(v.tail[max(start-lm, 0) : end-lm])
	}
}

func k12SumParallel(p permKind, custom, msg []byte, workers int) (out [32]byte) {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	tail := make([]byte, 0, len(custom)+9)
	tail = append(append(tail, custom...), right_encode(uint64(len(custom)))...)
	S := virtualS{msg: msg, tail: tail}
	total := S.len()

	if total <= maxChunk { // single node
		s := state{rate: 168, dsbyte: 0x07, perm: p}
		S.write(&s, 0, total)
		s.Read(out[:])
		return
	}

	n := (total + maxChunk - 1) / maxChunk // number of chunks
	cvs := make([][32]byte, n-1)           // CV_1 .. CV_{n-1}
	leaf := func(i int) {                  // chunk index i >= 1
		s := state{rate: 168, dsbyte: 0x0b, perm: p}
		S.write(&s, i*maxChunk, min((i+1)*maxChunk, total))
		s.Read(cvs[i-1][:])
	}

	if workers = min(workers, n-1); workers < 2 || n-1 < ParallelMinChunks {
		for i := 1; i < n; i++ {
			leaf(i)
		}
	} else {
		// Contiguous ranges keep each goroutine streaming through memory.
		var wg sync.WaitGroup
		per := (n - 1 + workers - 1) / workers
		for lo := 1; lo < n; lo += per {
			hi := min(lo+per, n)
			wg.Add(1)
			go func(lo, hi int) {
				defer wg.Done()
				for i := lo; i < hi; i++ {
					leaf(i)
				}
			}(lo, hi)
		}
		wg.Wait()
	}

	s := state{rate: 168, dsbyte: 0x06, perm: p}
	S.write(&s, 0, maxChunk)
	s.Write(firstChunkSuffix[:])
	for i := range cvs {
		s.Write(cvs[i][:])
	}
	s.Write(right_encode(uint64(n - 1)))
	s.Write(treeSuffix[:])
	s.Read(out[:])
	return
}
