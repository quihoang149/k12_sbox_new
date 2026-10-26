package chain

import (
	"errors"
	"math/big"
	"time"
)

// PoWEngine is proof of work with Ethereum-style difficulty adjustment:
// the difficulty follows the network's hash rate so that blocks keep
// arriving every TargetBlockMs. That is why, under PoW, a faster hash
// function does not make the chain faster: difficulty simply rises.
type PoWEngine struct {
	InitialDifficulty uint64
	TargetBlockMs     uint64 // 0 = fixed difficulty
	Reward            uint64
	Now               func() uint64 // ms clock; nil = wall clock
}

func NewPoWEngine(initialDifficulty, targetBlockMs uint64) *PoWEngine {
	return &PoWEngine{InitialDifficulty: initialDifficulty, TargetBlockMs: targetBlockMs, Reward: 2_000_000_000}
}

func (e *PoWEngine) Name() string { return "PoW" }

func (e *PoWEngine) now() uint64 {
	if e.Now != nil {
		return e.Now()
	}
	return uint64(time.Now().UnixMilli())
}

func (e *PoWEngine) InitGenesis(h Hasher, g *Header, st *StateDB) {
	g.Difficulty = e.InitialDifficulty
}

// CalcDifficulty returns the difficulty of a block with timestamp t on top
// of parent. Like Ethereum's rule, the change is linear in the time since
// the parent, so the average block time converges to the target:
//
//	d' = d * (1 + (target - actual) / (4*target)),  clamped to [d/2, 2d].
func (e *PoWEngine) CalcDifficulty(parent *Header, t uint64) uint64 {
	d := parent.Difficulty
	if e.TargetBlockMs == 0 || parent.Number == 0 {
		return d
	}
	T := e.TargetBlockMs
	actual := t - parent.Time
	if actual >= 3*T { // factor would drop to <= 1/2
		return max(d/2, 1)
	}
	nd := new(big.Int).SetUint64(d)
	nd.Mul(nd, new(big.Int).SetUint64(5*T-actual))
	nd.Div(nd, new(big.Int).SetUint64(4*T))
	return max(nd.Uint64(), d/2, 1) // nd <= 1.25d, no overflow concern
}

func (e *PoWEngine) Prepare(bc *Blockchain, b *Block) error {
	parent := &bc.Head().Header
	hd := &b.Header
	hd.Time = max(e.now(), parent.Time+1)
	hd.Difficulty = e.CalcDifficulty(parent, hd.Time)
	return nil
}

func (e *PoWEngine) Finalize(bc *Blockchain, st *StateDB, b *Block) {
	st.AddBalance(b.Header.Coinbase, e.Reward)
}

func (e *PoWEngine) Seal(bc *Blockchain, b *Block) (SealInfo, error) {
	n, ok := Seal(bc.H, &b.Header, nil)
	if !ok {
		return SealInfo{Attempts: n}, errors.New("sealing aborted")
	}
	return SealInfo{Attempts: n}, nil
}

var (
	ErrBadTime       = errors.New("bad timestamp")
	ErrBadDifficulty = errors.New("wrong difficulty")
	ErrBadPoW        = errors.New("invalid proof of work")
	ErrPoSFields     = errors.New("PoS fields set in a PoW block")
)

func (e *PoWEngine) VerifyConsensus(bc *Blockchain, parent, b *Block) error {
	hd := &b.Header
	if hd.Time <= parent.Header.Time || hd.Time > e.now()+15_000 {
		return ErrBadTime
	}
	if hd.Difficulty != e.CalcDifficulty(&parent.Header, hd.Time) {
		return ErrBadDifficulty
	}
	if hd.Slot != 0 || hd.ProposerIndex != 0 || hd.RandaoMix != (Hash{}) ||
		len(b.Attestations) != 0 || len(b.Slashings) != 0 || b.Signature != nil {
		return ErrPoSFields
	}
	if !CheckPoW(bc.H, hd) {
		return ErrBadPoW
	}
	return nil
}

func (e *PoWEngine) VerifySeal(bc *Blockchain, b *Block) error {
	if !CheckPoW(bc.H, &b.Header) {
		return ErrBadPoW
	}
	return nil
}

func (e *PoWEngine) Committed(bc *Blockchain, b *Block) {}

// ---- proof-of-work puzzle ----

var two256 = new(big.Int).Lsh(big.NewInt(1), 256)

// Target returns 2^256 / difficulty.
func Target(difficulty uint64) *big.Int {
	if difficulty == 0 {
		difficulty = 1
	}
	return new(big.Int).Div(two256, new(big.Int).SetUint64(difficulty))
}

func powHash(h Hasher, seal Hash, nonce uint64) Hash {
	return h.Sum(seal[:], u64(nonce))
}

// CheckPoW verifies H(sealHash || nonce) <= target.
func CheckPoW(h Hasher, hd *Header) bool {
	d := powHash(h, hd.SealHash(h), hd.Nonce)
	return new(big.Int).SetBytes(d[:]).Cmp(Target(hd.Difficulty)) <= 0
}

// Seal searches for a nonce and returns how many hashes it took.
// stop (optional) aborts the search when closed.
func Seal(h Hasher, hd *Header, stop <-chan struct{}) (attempts uint64, ok bool) {
	seal := hd.SealHash(h)
	target := Target(hd.Difficulty)
	v := new(big.Int)
	for nonce := uint64(0); ; nonce++ {
		if stop != nil && nonce&0xfff == 0 {
			select {
			case <-stop:
				return nonce, false
			default:
			}
		}
		d := powHash(h, seal, nonce)
		if v.SetBytes(d[:]).Cmp(target) <= 0 {
			hd.Nonce = nonce
			return nonce + 1, true
		}
	}
}
