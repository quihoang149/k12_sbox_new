// Command demo runs the Ethereum-style chain end to end and compares
// Keccak-256 with KangarooTwelve under PoW and PoS.
//
//	go run ./cmd/demo                         # PoS and PoW, both hashes
//	go run ./cmd/demo -consensus pos -blocks 20 -users 5000
//	go run ./cmd/demo -consensus pos -offline 0.4   # finality stalls
//	go run ./cmd/demo -consensus pow -target 50     # difficulty adapts
//
// Two nodes run in each experiment: a producer (proposer/miner) and a
// follower that imports and fully validates every block, as any other node
// in the network would.
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"k12chain/chain"
)

type opts struct {
	blocks, txs, users, validators int
	offline                        float64
	slashing                       bool
	diff, target                   uint64
	seed                           int64
	quiet                          bool
	workers                        int
}

func main() {
	var o opts
	cons := flag.String("consensus", "both", "pos | pow | both")
	hashName := flag.String("hash", "both",
		"comma-separated list of "+strings.Join(chain.HasherNames, ", ")+
			"; or both (keccak,k12), sbox (keccak,keccak-go,k12sbox), all")
	flag.IntVar(&o.blocks, "blocks", 20, "number of blocks")
	flag.IntVar(&o.txs, "txs", 100, "transactions per block")
	flag.IntVar(&o.users, "users", 5000, "number of accounts (state size)")
	flag.IntVar(&o.validators, "validators", 32, "PoS: number of validators")
	flag.Float64Var(&o.offline, "offline", 0, "PoS: fraction of validators offline (0..1)")
	flag.BoolVar(&o.slashing, "slashing", true, "PoS: demonstrate slashing of a double-signer")
	flag.Uint64Var(&o.diff, "difficulty", 1<<14, "PoW: initial difficulty")
	flag.Uint64Var(&o.target, "target", 50, "PoW: target block time in ms (0 = fixed difficulty)")
	flag.Int64Var(&o.seed, "seed", 1, "random seed for the workload")
	flag.BoolVar(&o.quiet, "quiet", false, "only print the summaries")
	flag.IntVar(&o.workers, "workers", 0, "threads per node for signatures and Merkle hashing (0 = all CPUs, 1 = sequential)")
	flag.Parse()
	if o.workers <= 0 {
		o.workers = chain.DefaultWorkers()
	}
	fmt.Printf("node threads: %d (use -workers 1 for a fully sequential node)\n", o.workers)

	hashes := strings.Split(*hashName, ",")
	switch *hashName {
	case "both":
		hashes = []string{"keccak", "k12"}
	case "sbox":
		hashes = []string{"keccak", "keccak-go", "k12sbox"}
	case "all":
		hashes = chain.HasherNames
	}
	modes := []string{*cons}
	if *cons == "both" {
		modes = []string{"pos", "pow"}
	}

	for _, mode := range modes {
		var results []result
		for _, name := range hashes {
			base, ok := chain.HasherByName(name)
			if !ok {
				fail(fmt.Errorf("unknown hash %q", name))
			}
			var r result
			var err error
			switch mode {
			case "pos":
				r, err = runPoS(base, o)
			case "pow":
				r, err = runPoW(base, o)
			default:
				err = fmt.Errorf("unknown consensus %q", mode)
			}
			if err != nil {
				fail(err)
			}
			results = append(results, r)
		}
		if mode == "pos" {
			comparePoS(results)
		} else {
			comparePoW(results, o)
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// ---- shared setup ----

type world struct {
	h      *chain.Counting
	keys   []*chain.Key
	addrs  []chain.Address
	alloc  map[chain.Address]uint64
	rng    *rand.Rand
	nonces []uint64
}

func newWorld(base chain.Hasher, o opts) (*world, error) {
	base = chain.WithWorkers(base, o.workers) // K12 tree mode for long inputs
	w := &world{h: chain.NewCounting(base), alloc: map[chain.Address]uint64{},
		rng: rand.New(rand.NewSource(o.seed)), nonces: make([]uint64, o.users)}
	for i := 0; i < o.users; i++ {
		k, err := chain.GenerateKey()
		if err != nil {
			return nil, err
		}
		w.keys = append(w.keys, k)
		w.addrs = append(w.addrs, k.Address(w.h))
		w.alloc[w.addrs[i]] = 1_000_000_000_000
	}
	return w, nil
}

// pending creates n signed transfers. Users sign before the block is built,
// so this cost is not part of block production.
func (w *world) pending(n int, chainID uint64) ([]*chain.Transaction, error) {
	txs := make([]*chain.Transaction, 0, n)
	for i := 0; i < n; i++ {
		from, to := w.rng.Intn(len(w.keys)), w.rng.Intn(len(w.keys))
		tx := &chain.Transaction{Nonce: w.nonces[from], GasPrice: 1, GasLimit: 21000,
			To: w.addrs[to], Value: uint64(w.rng.Intn(1000) + 1), ChainID: chainID}
		if err := tx.Sign(w.h, w.keys[from]); err != nil {
			return nil, err
		}
		w.nonces[from]++
		txs = append(txs, tx)
	}
	return txs, nil
}

type result struct {
	hash      string
	blocks    int
	txs       int
	build     time.Duration // producer: prepare + execute + roots (+ PoS signing)
	seal      time.Duration
	importT   time.Duration // follower: full validation + execution
	hashT     time.Duration // time inside the hash function (both nodes)
	hashCalls uint64
	finalized uint64
	slot      uint64
	// PoW, measured over the second half (after difficulty settled)
	steadyBlocks int
	steadyTime   time.Duration
	steadyDiff   float64
	steadyTries  uint64
	steadySeal   time.Duration
}

func ms(d time.Duration) string { return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000) }

func pct(a, b time.Duration) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

// ---- PoS ----

func runPoS(base chain.Hasher, o opts) (result, error) {
	w, err := newWorld(base, o)
	if err != nil {
		return result{}, err
	}
	h := w.h
	vals, vkeys, err := chain.GenerateValidators(h, o.validators, 32_000_000_000)
	if err != nil {
		return result{}, err
	}
	engine := chain.NewPoSEngine(vals, vkeys)
	vrng := rand.New(rand.NewSource(o.seed + 1))
	for _, i := range vrng.Perm(o.validators)[:int(o.offline*float64(o.validators))] {
		engine.Offline[i] = true
	}
	cfg := chain.DefaultConfig()
	cfg.Workers = o.workers
	producer := chain.NewBlockchain(h, cfg, engine, w.alloc)
	follower := chain.NewBlockchain(h, cfg, chain.NewPoSEngine(vals, nil), w.alloc)

	r := result{hash: h.Name()}
	fmt.Printf("\n================ PoS / %s ================\n", h.Name())
	fmt.Printf("genesis %s\naccounts=%d validators=%d (offline %d)  slot=%ds\n",
		follower.Genesis().Hash(h).Hex(), o.users, o.validators, len(engine.Offline), engine.SlotMs/1000)
	if !o.quiet {
		fmt.Printf("\n%-4s %-5s %-5s %4s %6s %5s %10s %10s %8s %6s\n",
			"#", "slot", "prop", "txs", "att%", "final", "build", "import", "hashes", "hash%")
	}

	slashAt := -1
	if o.slashing && o.blocks >= 4 {
		slashAt = o.blocks / 2
	}
	h.Timing = true
	for i := 0; i < o.blocks; i++ {
		txs, err := w.pending(o.txs, cfg.ChainID)
		if err != nil {
			return r, err
		}
		if i == slashAt {
			// Some validator signs two different blocks for an old slot;
			// the evidence reaches the next proposer.
			victim := (int(producer.Head().Header.ProposerIndex) + 1) % o.validators
			ev, err := engine.DoubleSign(h, victim, producer.Head().Header.Slot)
			if err != nil {
				return r, err
			}
			engine.SubmitEvidence(ev)
		}

		h.Reset()
		blk, st, err := producer.ProduceBlock(txs, chain.Address{})
		if err != nil {
			return r, err
		}
		t0 := time.Now()
		if err := follower.InsertBlock(blk); err != nil {
			return r, fmt.Errorf("follower rejected block %d: %w", blk.Header.Number, err)
		}
		imp := time.Since(t0)
		calls, _ := h.Stats()
		ht := h.HashTime()

		r.blocks++
		r.txs += st.Included
		r.build += st.Build + st.Seal
		r.importT += imp
		r.hashT += ht
		r.hashCalls += calls

		if !o.quiet {
			fmt.Printf("%-4d %-5d %-5d %4d %6.1f %5d %10s %10s %8d %5.1f%%\n",
				blk.Header.Number, blk.Header.Slot, blk.Header.ProposerIndex, st.Included,
				chain.AttestedPercent(follower.State(), blk), follower.Finalized,
				ms(st.Build+st.Seal), ms(imp), calls, pct(ht, st.Build+st.Seal+imp))
		}
		for _, s := range blk.Slashings {
			v := follower.State().Validators()[s.Validator]
			fmt.Printf("     ↳ slashed validator %d for double-signing slot %d: stake %d -> %d, ejected\n",
				s.Validator, s.Slot, vals[s.Validator].Stake, v.Stake)
		}
	}
	h.Timing = false
	r.finalized = follower.Finalized
	r.slot = follower.Head().Header.Slot

	if follower.State().Root(h) != producer.State().Root(h) {
		return r, fmt.Errorf("producer and follower states diverged")
	}
	if err := follower.Verify(); err != nil {
		return r, fmt.Errorf("chain verification failed: %w", err)
	}
	fmt.Printf("\nfollower node: chain verification OK, state root matches producer\n")
	fmt.Printf("head slot %d (%d empty slots), finalized block %d of %d\n",
		r.slot, int(r.slot)-r.blocks, r.finalized, r.blocks)
	tamperAndProof(follower, h)
	return r, nil
}

func comparePoS(rs []result) {
	fmt.Printf("\n################ PoS summary (per block, averages) ################\n")
	fmt.Printf("%-11s %11s %11s %10s %8s %16s\n", "hash", "produce", "import", "hashes", "hash%", "node capacity")
	for _, r := range rs {
		n := time.Duration(r.blocks)
		fmt.Printf("%-11s %11s %11s %10d %7.1f%% %11.0f tx/s\n",
			r.hash, ms(r.build/n), ms(r.importT/n), r.hashCalls/uint64(r.blocks),
			pct(r.hashT, r.build+r.importT), float64(r.txs)/r.importT.Seconds())
	}
	if len(rs) >= 2 {
		base := rs[0]
		fmt.Println()
		for _, r := range rs[1:] {
			fmt.Printf("%s vs %s: produce %.2fx, import %.2fx  (>1 = faster)\n", r.hash, base.hash,
				float64(base.build)/float64(r.build), float64(base.importT)/float64(r.importT))
		}
		fmt.Println("In PoS the slot length is fixed, so saved time is pure headroom:")
		fmt.Println("larger blocks or slower hardware fit in the same slot.")
	}
	fmt.Println("(hash% includes timing overhead and, with several threads, sums CPU time")
	fmt.Println(" over threads, so it can exceed the wall-clock share; capacity = txs / import time)")
}

// ---- PoW ----

func runPoW(base chain.Hasher, o opts) (result, error) {
	w, err := newWorld(base, o)
	if err != nil {
		return result{}, err
	}
	h := w.h
	cfg := chain.DefaultConfig()
	cfg.Workers = o.workers
	producer := chain.NewBlockchain(h, cfg, chain.NewPoWEngine(o.diff, o.target), w.alloc)
	follower := chain.NewBlockchain(h, cfg, chain.NewPoWEngine(o.diff, o.target), w.alloc)
	miner := w.addrs[0]

	r := result{hash: h.Name()}
	fmt.Printf("\n================ PoW / %s ================\n", h.Name())
	fmt.Printf("genesis %s\naccounts=%d  initial difficulty=%d  target block time=%dms\n",
		follower.Genesis().Hash(h).Hex(), o.users, o.diff, o.target)
	if !o.quiet {
		fmt.Printf("\n%-4s %4s %11s %9s %10s %10s %10s\n",
			"#", "txs", "difficulty", "tries", "build", "seal", "import")
	}
	for i := 0; i < o.blocks; i++ {
		txs, err := w.pending(o.txs, cfg.ChainID)
		if err != nil {
			return r, err
		}
		blk, st, err := producer.ProduceBlock(txs, miner)
		if err != nil {
			return r, err
		}
		t0 := time.Now()
		if err := follower.InsertBlock(blk); err != nil {
			return r, fmt.Errorf("follower rejected block %d: %w", blk.Header.Number, err)
		}
		imp := time.Since(t0)
		r.blocks++
		r.txs += st.Included
		r.build += st.Build
		r.seal += st.Seal
		r.importT += imp
		if i >= o.blocks/2 {
			// Block interval as the network sees it: timestamp difference.
			parentTime := producer.Block(int(blk.Header.Number) - 1).Header.Time
			r.steadyBlocks++
			r.steadyTime += time.Duration(blk.Header.Time-parentTime) * time.Millisecond
			r.steadyDiff += float64(blk.Header.Difficulty)
			r.steadyTries += st.Attempts
			r.steadySeal += st.Seal
		}
		if !o.quiet {
			fmt.Printf("%-4d %4d %11d %9d %10s %10s %10s\n", blk.Header.Number, st.Included,
				blk.Header.Difficulty, st.Attempts, ms(st.Build), ms(st.Seal), ms(imp))
		}
	}
	if err := follower.Verify(); err != nil {
		return r, fmt.Errorf("chain verification failed: %w", err)
	}
	fmt.Printf("\nfollower node: chain verification OK\n")
	tamperAndProof(follower, h)
	return r, nil
}

func comparePoW(rs []result, o opts) {
	fmt.Printf("\n################ PoW summary (second half of the run) ################\n")
	fmt.Printf("%-11s %14s %15s %12s %12s\n", "hash", "avg difficulty", "block interval", "hash rate", "throughput")
	for _, r := range rs {
		if r.steadyBlocks == 0 {
			continue
		}
		n := float64(r.steadyBlocks)
		bt := r.steadyTime / time.Duration(r.steadyBlocks)
		fmt.Printf("%-11s %14.0f %15s %9.2f MH/s %8.0f tx/s\n", r.hash, r.steadyDiff/n, ms(bt),
			float64(r.steadyTries)/r.steadySeal.Seconds()/1e6, float64(o.txs)/bt.Seconds())
	}
	if o.target > 0 {
		fmt.Printf("\nTarget block time is %dms. A faster hash raises the hash rate, the\n", o.target)
		fmt.Println("difficulty rises to match, and the block time (and throughput) returns")
		fmt.Println("to the target: the speed-up is absorbed by the puzzle.")
		fmt.Println("(Block intervals are random; use -blocks 100 or more for stable averages.)")
	}
}

// ---- common checks ----

func tamperAndProof(bc *chain.Blockchain, h chain.Hasher) {
	last := bc.Head()
	if len(last.Txs) > 0 {
		leaves := make([][]byte, len(last.Txs))
		for i, tx := range last.Txs {
			leaves[i] = tx.RLP()
		}
		idx := len(leaves) / 2
		proof := chain.MerkleProof(h, leaves, idx)
		fmt.Printf("merkle proof for tx %d of block %d: %d steps, valid=%v\n", idx,
			last.Header.Number, len(proof), chain.VerifyMerkleProof(h, last.Header.TxRoot, leaves[idx], proof))
	}
	if bc.Len() > 1 && len(bc.Block(1).Txs) > 0 {
		tx := bc.Block(1).Txs[0]
		tx.Value++
		err := bc.Verify()
		tx.Value--
		msg := "NOT DETECTED"
		if err != nil {
			msg = err.Error()
		}
		fmt.Printf("tamper test (edit a tx value in block 1): %s\n", strings.TrimSpace(msg))
	}
}
