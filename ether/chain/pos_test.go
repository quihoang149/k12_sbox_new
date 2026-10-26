package chain

import (
	"errors"
	"testing"
)

type posNet struct {
	producer, follower *Blockchain
	engine             *PoSEngine
	keys               []*Key
	addrs              []Address
	vals               []Validator
}

func newPoSNet(t testing.TB, h Hasher, nUsers, nVals int) *posNet {
	return newPoSNetSized(t, h, nUsers, nVals, 0)
}

// newPoSNetSized adds filler accounts (funded, without keys) so the state
// can be made large cheaply.
func newPoSNetSized(t testing.TB, h Hasher, nUsers, nVals, filler int) *posNet {
	vals, vkeys, err := GenerateValidators(h, nVals, 32_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	n := &posNet{vals: vals}
	alloc := map[Address]uint64{}
	for i := 0; i < nUsers; i++ {
		k, _ := GenerateKey()
		n.keys = append(n.keys, k)
		n.addrs = append(n.addrs, k.Address(h))
		alloc[n.addrs[i]] = 1_000_000_000
	}
	for i := 0; i < filler; i++ {
		alloc[PubToAddress(h, u64(uint64(i)))] = 1
	}
	n.engine = NewPoSEngine(vals, vkeys)
	n.producer = NewBlockchain(h, DefaultConfig(), n.engine, alloc)
	n.follower = NewBlockchain(h, DefaultConfig(), NewPoSEngine(vals, nil), alloc) // no keys: verify only
	if n.producer.Genesis().Hash(h) != n.follower.Genesis().Hash(h) {
		t.Fatal("genesis differs between nodes")
	}
	return n
}

func (n *posNet) transfers(h Hasher, count int, nonces []uint64) []*Transaction {
	var txs []*Transaction
	for i := 0; i < count; i++ {
		from := i % len(n.keys)
		tx := &Transaction{Nonce: nonces[from], GasPrice: 1, GasLimit: 21000,
			To: n.addrs[(i+1)%len(n.addrs)], Value: 5, ChainID: n.producer.Cfg.ChainID}
		tx.Sign(h, n.keys[from])
		nonces[from]++
		txs = append(txs, tx)
	}
	return txs
}

func TestPoSChainAndFinality(t *testing.T) {
	for _, h := range hashers {
		n := newPoSNet(t, h, 10, 8)
		nonces := make([]uint64, 10)
		for i := 0; i < 5; i++ {
			blk, _, err := n.producer.ProduceBlock(n.transfers(h, 10, nonces), Address{})
			if err != nil {
				t.Fatalf("%s: produce: %v", h.Name(), err)
			}
			if err := n.follower.InsertBlock(blk); err != nil {
				t.Fatalf("%s: follower rejected block %d: %v", h.Name(), i+1, err)
			}
			if got := AttestedPercent(n.follower.State(), blk); got != 100 {
				t.Fatalf("attested %.1f%%, want 100", got)
			}
		}
		if n.follower.State().Root(h) != n.producer.State().Root(h) {
			t.Fatal("state diverged")
		}
		if n.follower.Finalized != 4 || n.producer.Finalized != 4 {
			t.Fatalf("finalized = %d/%d, want 4", n.producer.Finalized, n.follower.Finalized)
		}
		if err := n.follower.Verify(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPoSProposerIsStakeWeighted(t *testing.T) {
	h := NewK12Hasher(nil)
	vals := []Validator{{Stake: 1}, {Stake: 3}}
	counts := [2]int{}
	var mix Hash
	for slot := uint64(0); slot < 20000; slot++ {
		i, _ := SelectProposer(h, vals, mix, slot)
		counts[i]++
	}
	// Expect ~25% / 75%.
	if counts[0] < 4500 || counts[0] > 5500 {
		t.Fatalf("selection not stake weighted: %v", counts)
	}
	vals[1].Slashed = true
	for slot := uint64(0); slot < 100; slot++ {
		if i, _ := SelectProposer(h, vals, mix, slot); i != 0 {
			t.Fatal("slashed validator selected")
		}
	}
}

func TestPoSOfflineValidators(t *testing.T) {
	h := NewK12Hasher(nil)
	n := newPoSNet(t, h, 2, 9)
	// Validators 0..8 have stakes 1,2,3,4,1,2,3,4,1 (x base) = 21 total.
	// Taking 1,2,3 offline removes 9/21 = 43% > 1/3: finality must stop,
	// but blocks keep coming (liveness of the chain, not of finality).
	n.engine.Offline = map[int]bool{1: true, 2: true, 3: true}
	for i := 0; i < 6; i++ {
		blk, _, err := n.producer.ProduceBlock(nil, Address{})
		if err != nil {
			t.Fatal(err)
		}
		if err := n.follower.InsertBlock(blk); err != nil {
			t.Fatal(err)
		}
	}
	if n.follower.Finalized != 0 {
		t.Fatalf("finalized %d with only 57%% online", n.follower.Finalized)
	}
	if n.follower.Head().Header.Slot <= 6 {
		t.Log("note: no slot skipped in this run (offline proposers not elected)")
	}
}

func TestPoSSlashing(t *testing.T) {
	h := NewKeccakHasher()
	n := newPoSNet(t, h, 2, 6)
	ev, _ := n.engine.DoubleSign(h, 3, 1)
	stake := n.vals[3].Stake
	n.engine.SubmitEvidence(ev)
	blk, _, err := n.producer.ProduceBlock(nil, Address{})
	if err != nil {
		t.Fatal(err)
	}
	if len(blk.Slashings) != 1 {
		t.Fatal("evidence not included")
	}
	if err := n.follower.InsertBlock(blk); err != nil {
		t.Fatal(err)
	}
	v := n.follower.State().Validators()[3]
	if !v.Slashed || v.Stake != stake-stake/32 {
		t.Fatalf("not slashed: %+v", v)
	}

	// Forged evidence (signatures from another validator) must be rejected.
	forged, _ := n.engine.DoubleSign(h, 4, 2)
	forged.Validator = 5
	n.engine.SubmitEvidence(forged)
	blk2, _, err := n.producer.ProduceBlock(nil, Address{})
	if err == nil {
		err = n.follower.InsertBlock(blk2)
	}
	if !errors.Is(err, ErrBadSlashing) {
		t.Fatalf("forged evidence: got %v", err)
	}
}

func TestPoSRejectsBadBlocks(t *testing.T) {
	h := NewK12Hasher(nil)
	cases := map[string]struct {
		mutate func(b *Block)
		want   error
	}{
		"proposer sig":    {func(b *Block) { b.Signature[0] ^= 1 }, ErrBadProposerSig},
		"wrong proposer":  {func(b *Block) { b.Header.ProposerIndex ^= 1 }, ErrWrongProposer},
		"randao":          {func(b *Block) { b.RandaoReveal[0] ^= 1 }, ErrBadRandao},
		"attestation sig": {func(b *Block) { b.Attestations[2].Sig[0] ^= 1 }, ErrBadConsRoot},
		"slot time":       {func(b *Block) { b.Header.Time++ }, ErrBadTime},
		"pow fields":      {func(b *Block) { b.Header.Difficulty = 1 }, ErrPoWFields},
	}
	for name, c := range cases {
		n := newPoSNet(t, h, 2, 6)
		blk, _, err := n.producer.ProduceBlock(nil, Address{})
		if err != nil {
			t.Fatal(err)
		}
		c.mutate(blk)
		if err := n.follower.InsertBlock(blk); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", name, err, c.want)
		}
	}

	// An attestation with a bad signature but a matching consensus root.
	n := newPoSNet(t, h, 2, 6)
	blk, _, _ := n.producer.ProduceBlock(nil, Address{})
	blk.Attestations[2].Sig[0] ^= 1
	blk.Header.ConsRoot = ConsensusRoot(h, blk)
	n.engine.Seal(n.producer, blk) // re-sign so only the attestation is wrong
	if err := n.follower.InsertBlock(blk); !errors.Is(err, ErrBadAttestation) {
		t.Errorf("bad attestation: got %v", err)
	}
}
