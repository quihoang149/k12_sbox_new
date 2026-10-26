package chain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// PoSEngine is a simplified Ethereum-style proof of stake (Gasper-like):
//
//   - time is divided into slots; each slot has one proposer, drawn with
//     probability proportional to stake from a RANDAO seed;
//   - the proposer contributes a RANDAO reveal (signature over the slot),
//     mixed into the seed so that no one can predict far-future proposers;
//   - the block carries attestations (votes) for its parent; once
//     validators holding >= 2/3 of the stake have voted, the parent is final;
//   - a proposer that signs two different blocks for one slot can be
//     slashed by anyone who includes both signatures as evidence.
//
// There is no puzzle: producing a block costs only the real work (execute
// transactions, hash state/tx/consensus roots, sign). Hash speed therefore
// translates directly into block processing time.
//
// Simplifications: validator keys are ed25519 (Ethereum: BLS12-381 with
// signature aggregation); every validator attests every slot (Ethereum:
// committees); finality is per block (Ethereum: per epoch via Casper FFG);
// the proposer seed comes from the parent's mix (Ethereum: epoch lookahead).
type PoSEngine struct {
	SlotMs         uint64 // slot length; Ethereum uses 12 000 ms
	ProposerReward uint64
	AttesterReward uint64

	genesis []Validator
	keys    []ed25519.PrivateKey // nil for a verifying-only node

	// Simulation knobs (producer side only).
	Offline  map[int]bool       // validators that neither propose nor attest
	evidence []SlashingEvidence // pending slashing evidence to include
}

// NewPoSEngine creates an engine for the given genesis validator set.
// keys may be nil for a node that only verifies blocks.
func NewPoSEngine(validators []Validator, keys []ed25519.PrivateKey) *PoSEngine {
	return &PoSEngine{
		SlotMs:         12_000,
		ProposerReward: 200_000_000,
		AttesterReward: 10_000_000,
		genesis:        validators,
		keys:           keys,
		Offline:        map[int]bool{},
	}
}

// GenerateValidators creates n validators. Stakes vary (1x..4x base) so
// that stake-weighted proposer selection is visible.
func GenerateValidators(h Hasher, n int, baseStake uint64) ([]Validator, []ed25519.PrivateKey, error) {
	vals := make([]Validator, n)
	keys := make([]ed25519.PrivateKey, n)
	for i := range vals {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		vals[i] = Validator{PubKey: pub, Withdrawal: PubToAddress(h, pub), Stake: baseStake * uint64(1+i%4)}
		keys[i] = priv
	}
	return vals, keys, nil
}

func (e *PoSEngine) Name() string { return "PoS" }

func (e *PoSEngine) InitGenesis(h Hasher, g *Header, st *StateDB) {
	for _, v := range e.genesis {
		st.AddValidator(v)
	}
	g.RandaoMix = h.Sum([]byte("genesis-randao"))
}

// ---- messages (domain separated, so a signature for one purpose can never
// be replayed as another) ----

type Attestation struct {
	Slot      uint64 // slot of the attested block
	BlockHash Hash
	Validator uint64
	Sig       []byte
}

func (a *Attestation) RLP() []byte {
	return rlpList(rlpUint(1), rlpUint(a.Slot), rlpBytes(a.BlockHash[:]), rlpUint(a.Validator), rlpBytes(a.Sig))
}

// SlashingEvidence proves that a validator signed two different blocks for
// the same slot.
type SlashingEvidence struct {
	Validator    uint64
	Slot         uint64
	HashA, HashB Hash
	SigA, SigB   []byte
}

func (s *SlashingEvidence) RLP() []byte {
	return rlpList(rlpUint(2), rlpUint(s.Validator), rlpUint(s.Slot),
		rlpBytes(s.HashA[:]), rlpBytes(s.SigA), rlpBytes(s.HashB[:]), rlpBytes(s.SigB))
}

func randaoMsg(h Hasher, slot uint64) Hash { return h.Sum([]byte("RANDAO"), u64(slot)) }

func attestMsg(h Hasher, slot uint64, bh Hash) Hash {
	return h.Sum([]byte("ATTEST"), u64(slot), bh[:])
}

func proposalMsg(h Hasher, slot, idx uint64, bh Hash) Hash {
	return h.Sum([]byte("PROPOSE"), u64(slot), u64(idx), bh[:])
}

func verifySig(pub []byte, msg Hash, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize &&
		ed25519.Verify(pub, msg[:], sig)
}

func xorHash(a, b Hash) (out Hash) {
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return
}

var (
	ErrNoProposer     = errors.New("no active validator")
	ErrNoKey          = errors.New("this node has no key for the elected proposer")
	ErrBadSlot        = errors.New("slot not after parent")
	ErrWrongProposer  = errors.New("wrong proposer for slot")
	ErrBadRandao      = errors.New("invalid RANDAO reveal or mix")
	ErrBadProposerSig = errors.New("invalid proposer signature")
	ErrBadAttestation = errors.New("invalid attestation")
	ErrBadSlashing    = errors.New("invalid slashing evidence")
	ErrPoWFields      = errors.New("PoW fields set in a PoS block")
)

// SelectProposer draws the proposer of slot, weighted by stake, from a seed
// derived from the RANDAO mix. Every node computes the same answer.
func SelectProposer(h Hasher, vals []Validator, mix Hash, slot uint64) (int, error) {
	var total uint64
	for i := range vals {
		if vals[i].Active() {
			total += vals[i].Stake
		}
	}
	if total == 0 {
		return 0, ErrNoProposer
	}
	seed := h.Sum([]byte("PROPOSER"), mix[:], u64(slot))
	r := binary.BigEndian.Uint64(seed[:8]) % total
	for i := range vals {
		if !vals[i].Active() {
			continue
		}
		if r < vals[i].Stake {
			return i, nil
		}
		r -= vals[i].Stake
	}
	return 0, ErrNoProposer // unreachable
}

func (e *PoSEngine) key(i int) ed25519.PrivateKey {
	if i < len(e.keys) {
		return e.keys[i]
	}
	return nil
}

// Prepare elects the proposer for the next slot that has an online
// proposer, adds the RANDAO reveal, collects attestations for the parent
// and includes pending slashing evidence.
func (e *PoSEngine) Prepare(bc *Blockchain, b *Block) error {
	h := bc.H
	parent := bc.Head()
	vals := bc.state.validators
	hd := &b.Header

	slot := parent.Header.Slot + 1
	var idx int
	for tries := 0; ; tries++ {
		i, err := SelectProposer(h, vals, parent.Header.RandaoMix, slot)
		if err != nil {
			return err
		}
		if !e.Offline[i] {
			idx = i
			break
		}
		if tries > 10_000 {
			return ErrNoProposer
		}
		slot++ // proposer offline: slot stays empty
	}
	key := e.key(idx)
	if key == nil {
		return ErrNoKey
	}

	hd.Slot = slot
	hd.ProposerIndex = uint64(idx)
	hd.Coinbase = vals[idx].Withdrawal
	hd.Time = bc.Genesis().Header.Time + slot*e.SlotMs

	msg := randaoMsg(h, slot)
	b.RandaoReveal = ed25519.Sign(key, msg[:]) // ed25519 is deterministic
	hd.RandaoMix = xorHash(parent.Header.RandaoMix, h.Sum(b.RandaoReveal))

	// Simulated network: every online validator has seen the parent and
	// votes for it. In reality each validator signs on its own machine, so
	// the signatures are produced in parallel here.
	ph := parent.Hash(h)
	am := attestMsg(h, parent.Header.Slot, ph)
	for i := range vals {
		if vals[i].Active() && !e.Offline[i] && e.key(i) != nil {
			b.Attestations = append(b.Attestations, Attestation{
				Slot: parent.Header.Slot, BlockHash: ph, Validator: uint64(i)})
		}
	}
	parallelFor(len(b.Attestations), bc.Cfg.Workers, 2, func(lo, hi int) {
		for j := lo; j < hi; j++ {
			a := &b.Attestations[j]
			a.Sig = ed25519.Sign(e.key(int(a.Validator)), am[:])
		}
	})

	for _, ev := range e.evidence {
		if int(ev.Validator) < len(vals) && !vals[ev.Validator].Slashed {
			b.Slashings = append(b.Slashings, ev)
		}
	}
	e.evidence = nil
	return nil
}

// Finalize pays the proposer and attesters and applies slashing.
func (e *PoSEngine) Finalize(bc *Blockchain, st *StateDB, b *Block) {
	st.AddBalance(b.Header.Coinbase, e.ProposerReward)
	for i := range b.Attestations {
		st.AddBalance(st.validators[b.Attestations[i].Validator].Withdrawal, e.AttesterReward)
	}
	for i := range b.Slashings {
		v := st.touchValidator(int(b.Slashings[i].Validator))
		v.Stake -= v.Stake / 32 // burned, as Ethereum's initial penalty
		v.Slashed = true        // ejected: no more proposing or attesting
	}
}

// Seal signs the block as its proposer.
func (e *PoSEngine) Seal(bc *Blockchain, b *Block) (SealInfo, error) {
	key := e.key(int(b.Header.ProposerIndex))
	if key == nil {
		return SealInfo{}, ErrNoKey
	}
	m := proposalMsg(bc.H, b.Header.Slot, b.Header.ProposerIndex, b.Hash(bc.H))
	b.Signature = ed25519.Sign(key, m[:])
	return SealInfo{}, nil
}

// VerifyConsensus is run by every node before executing the block.
func (e *PoSEngine) VerifyConsensus(bc *Blockchain, parent, b *Block) error {
	h := bc.H
	hd := &b.Header
	vals := bc.state.validators

	if hd.Difficulty != 0 || hd.Nonce != 0 {
		return ErrPoWFields
	}
	if hd.Slot <= parent.Header.Slot {
		return ErrBadSlot
	}
	if hd.Time != bc.Genesis().Header.Time+hd.Slot*e.SlotMs {
		return ErrBadTime
	}
	idx, err := SelectProposer(h, vals, parent.Header.RandaoMix, hd.Slot)
	if err != nil {
		return err
	}
	if uint64(idx) != hd.ProposerIndex || hd.Coinbase != vals[idx].Withdrawal {
		return ErrWrongProposer
	}
	pub := vals[idx].PubKey

	if !verifySig(pub, randaoMsg(h, hd.Slot), b.RandaoReveal) ||
		hd.RandaoMix != xorHash(parent.Header.RandaoMix, h.Sum(b.RandaoReveal)) {
		return ErrBadRandao
	}

	ph := parent.Hash(h)
	am := attestMsg(h, parent.Header.Slot, ph)
	seen := make(map[uint64]bool, len(b.Attestations))
	for i := range b.Attestations {
		a := &b.Attestations[i]
		if a.Slot != parent.Header.Slot || a.BlockHash != ph || a.Validator >= uint64(len(vals)) ||
			seen[a.Validator] || !vals[a.Validator].Active() {
			return fmt.Errorf("%w #%d", ErrBadAttestation, i)
		}
		seen[a.Validator] = true
	}
	// Signature checks are independent: verify them in parallel.
	sigOK := make([]bool, len(b.Attestations))
	parallelFor(len(b.Attestations), bc.Cfg.Workers, 2, func(lo, hi int) {
		for j := lo; j < hi; j++ {
			a := &b.Attestations[j]
			sigOK[j] = verifySig(vals[a.Validator].PubKey, am, a.Sig)
		}
	})
	for i, ok := range sigOK {
		if !ok {
			return fmt.Errorf("%w #%d", ErrBadAttestation, i)
		}
	}

	slashed := map[uint64]bool{}
	for i := range b.Slashings {
		s := &b.Slashings[i]
		if s.Validator >= uint64(len(vals)) || vals[s.Validator].Slashed || slashed[s.Validator] ||
			s.HashA == s.HashB ||
			!verifySig(vals[s.Validator].PubKey, proposalMsg(h, s.Slot, s.Validator, s.HashA), s.SigA) ||
			!verifySig(vals[s.Validator].PubKey, proposalMsg(h, s.Slot, s.Validator, s.HashB), s.SigB) {
			return fmt.Errorf("%w #%d", ErrBadSlashing, i)
		}
		slashed[s.Validator] = true
	}

	return e.VerifySeal(bc, b)
}

func (e *PoSEngine) VerifySeal(bc *Blockchain, b *Block) error {
	vals := bc.state.validators
	idx := b.Header.ProposerIndex
	if idx >= uint64(len(vals)) ||
		!verifySig(vals[idx].PubKey, proposalMsg(bc.H, b.Header.Slot, idx, b.Hash(bc.H)), b.Signature) {
		return ErrBadProposerSig
	}
	return nil
}

// Committed marks the parent final if >= 2/3 of active stake attested to it.
func (e *PoSEngine) Committed(bc *Blockchain, b *Block) {
	if pct := AttestedPercent(bc.state, b); pct*3 >= 200 && b.Header.Number > 0 {
		bc.Finalized = max(bc.Finalized, b.Header.Number-1)
	}
}

// AttestedPercent returns the share (0..100) of active stake that attested
// to b's parent.
func AttestedPercent(st *StateDB, b *Block) float64 {
	total := st.TotalActiveStake()
	if total == 0 {
		return 0
	}
	var att uint64
	for i := range b.Attestations {
		if v := &st.validators[b.Attestations[i].Validator]; v.Active() {
			att += v.Stake
		}
	}
	return 100 * float64(att) / float64(total)
}

// ---- simulation helpers ----

// DoubleSign makes validator idx sign two conflicting blocks for slot and
// returns the resulting evidence (what an honest node would observe).
func (e *PoSEngine) DoubleSign(h Hasher, idx int, slot uint64) (SlashingEvidence, error) {
	key := e.key(idx)
	if key == nil {
		return SlashingEvidence{}, ErrNoKey
	}
	a := h.Sum([]byte("fork A"), u64(slot))
	bb := h.Sum([]byte("fork B"), u64(slot))
	ma, mb := proposalMsg(h, slot, uint64(idx), a), proposalMsg(h, slot, uint64(idx), bb)
	return SlashingEvidence{
		Validator: uint64(idx), Slot: slot,
		HashA: a, SigA: ed25519.Sign(key, ma[:]),
		HashB: bb, SigB: ed25519.Sign(key, mb[:]),
	}, nil
}

// SubmitEvidence queues slashing evidence for the next block this node produces.
func (e *PoSEngine) SubmitEvidence(ev SlashingEvidence) { e.evidence = append(e.evidence, ev) }
