package chain

import (
	"errors"
	"fmt"
	"time"
)

// Config holds consensus-independent chain parameters.
type Config struct {
	ChainID  uint64
	GasLimit uint64 // per block
	// Workers is the number of threads a node uses for signature checks and
	// Merkle hashing (see parallel.go). 0 or 1 = fully sequential.
	Workers int
}

func DefaultConfig() Config {
	return Config{ChainID: 1337, GasLimit: 30_000_000, Workers: 1}
}

// Blockchain keeps the canonical chain and the head state of one node.
type Blockchain struct {
	H      Hasher
	Cfg    Config
	Engine Engine

	blocks []*Block
	state  *StateDB

	// Finalized is the highest block number that can no longer be reverted
	// (PoS only: reached when >= 2/3 of stake attested to it).
	Finalized uint64
}

// NewBlockchain builds the genesis block. Two nodes created with the same
// arguments have the same genesis hash.
func NewBlockchain(h Hasher, cfg Config, engine Engine, alloc map[Address]uint64) *Blockchain {
	st := NewStateDB()
	for a, v := range alloc {
		st.AddBalance(a, v)
	}
	g := &Block{Header: Header{GasLimit: cfg.GasLimit, TxRoot: TxRoot(h, nil)}}
	engine.InitGenesis(h, &g.Header, st)
	st.Commit()
	g.Header.StateRoot = st.Root(h)
	g.Header.ConsRoot = ConsensusRoot(h, g)
	return &Blockchain{H: h, Cfg: cfg, Engine: engine, blocks: []*Block{g}, state: st}
}

// Clone returns an independent copy of the node (shares immutable blocks).
func (bc *Blockchain) Clone() *Blockchain {
	c := *bc
	c.blocks = append([]*Block(nil), bc.blocks...)
	c.state = bc.state.Copy()
	return &c
}

func (bc *Blockchain) Head() *Block       { return bc.blocks[len(bc.blocks)-1] }
func (bc *Blockchain) Genesis() *Block    { return bc.blocks[0] }
func (bc *Blockchain) Len() int           { return len(bc.blocks) }
func (bc *Blockchain) Block(i int) *Block { return bc.blocks[i] }
func (bc *Blockchain) State() *StateDB    { return bc.state }

// BlockStats reports where the time went while producing a block.
type BlockStats struct {
	Build    time.Duration // consensus prep + executing txs + computing roots
	Seal     time.Duration // PoW search or PoS signature
	Attempts uint64        // PoW hashes tried
	Included int
	Dropped  int
}

// ProduceBlock builds a block on the head from pending txs (dropping
// invalid ones), seals it and makes it the new head. coinbase is used by
// PoW; PoS uses the elected proposer's address.
func (bc *Blockchain) ProduceBlock(pending []*Transaction, coinbase Address) (*Block, BlockStats, error) {
	var st BlockStats
	h := bc.H
	t0 := time.Now()

	parent := bc.Head()
	b := &Block{Header: Header{
		ParentHash: parent.Hash(h),
		Coinbase:   coinbase,
		Number:     parent.Header.Number + 1,
		GasLimit:   bc.Cfg.GasLimit,
	}}
	if err := bc.Engine.Prepare(bc, b); err != nil {
		return nil, st, err
	}
	hd := &b.Header
	hd.ConsRoot = ConsensusRoot(h, b)

	snap := bc.state.Snapshot()
	senders := recoverSenders(h, pending, bc.Cfg.Workers)
	var gasUsed uint64
	for i, tx := range pending {
		if gasUsed+tx.GasLimit > bc.Cfg.GasLimit {
			st.Dropped++
			continue
		}
		g, err := bc.state.applyWithSender(tx, senders[i].from, senders[i].err, hd.Coinbase, bc.Cfg.ChainID)
		if err != nil { // state untouched on error
			st.Dropped++
			continue
		}
		gasUsed += g
		b.Txs = append(b.Txs, tx)
	}
	bc.Engine.Finalize(bc, bc.state, b)
	hd.GasUsed = gasUsed
	hd.TxRoot = TxRootP(h, b.Txs, bc.Cfg.Workers)
	hd.StateRoot = bc.state.RootP(h, bc.Cfg.Workers)
	st.Build = time.Since(t0)
	st.Included = len(b.Txs)

	t1 := time.Now()
	info, err := bc.Engine.Seal(bc, b)
	st.Seal = time.Since(t1)
	st.Attempts = info.Attempts
	if err != nil {
		bc.state.RevertTo(snap)
		return nil, st, err
	}

	bc.state.Commit()
	bc.blocks = append(bc.blocks, b)
	bc.Engine.Committed(bc, b)
	return b, st, nil
}

var (
	ErrUnknownParent = errors.New("unknown or non-head parent")
	ErrBadNumber     = errors.New("bad block number")
	ErrBadTxRoot     = errors.New("tx root mismatch")
	ErrBadConsRoot   = errors.New("consensus root mismatch")
	ErrBadStateRoot  = errors.New("state root mismatch")
	ErrBadGas        = errors.New("gas used mismatch or over limit")
)

// InsertBlock fully validates b against the head and appends it.
// This is what every other node in the network runs for each block.
func (bc *Blockchain) InsertBlock(b *Block) error {
	h := bc.H
	parent := bc.Head()
	hd := &b.Header

	if hd.ParentHash != parent.Hash(h) {
		return ErrUnknownParent
	}
	if hd.Number != parent.Header.Number+1 {
		return ErrBadNumber
	}
	if TxRootP(h, b.Txs, bc.Cfg.Workers) != hd.TxRoot {
		return ErrBadTxRoot
	}
	if ConsensusRoot(h, b) != hd.ConsRoot {
		return ErrBadConsRoot
	}
	if err := bc.Engine.VerifyConsensus(bc, parent, b); err != nil {
		return err
	}
	senders := recoverSenders(h, b.Txs, bc.Cfg.Workers)

	snap := bc.state.Snapshot()
	fail := func(err error) error {
		bc.state.RevertTo(snap)
		return err
	}
	var gasUsed uint64
	for i, tx := range b.Txs {
		g, err := bc.state.applyWithSender(tx, senders[i].from, senders[i].err, hd.Coinbase, bc.Cfg.ChainID)
		if err != nil {
			return fail(fmt.Errorf("tx %d: %w", i, err))
		}
		gasUsed += g
	}
	if gasUsed != hd.GasUsed || gasUsed > hd.GasLimit || hd.GasLimit != bc.Cfg.GasLimit {
		return fail(ErrBadGas)
	}
	bc.Engine.Finalize(bc, bc.state, b)
	if bc.state.RootP(h, bc.Cfg.Workers) != hd.StateRoot {
		return fail(ErrBadStateRoot)
	}

	bc.state.Commit()
	bc.blocks = append(bc.blocks, b)
	bc.Engine.Committed(bc, b)
	return nil
}

// Verify re-checks hash links, roots and seals of the stored chain.
func (bc *Blockchain) Verify() error {
	for i := 1; i < len(bc.blocks); i++ {
		b, p := bc.blocks[i], bc.blocks[i-1]
		if b.Header.ParentHash != p.Hash(bc.H) {
			return fmt.Errorf("block %d: broken parent link", i)
		}
		if TxRoot(bc.H, b.Txs) != b.Header.TxRoot {
			return fmt.Errorf("block %d: %w", i, ErrBadTxRoot)
		}
		if ConsensusRoot(bc.H, b) != b.Header.ConsRoot {
			return fmt.Errorf("block %d: %w", i, ErrBadConsRoot)
		}
		if err := bc.Engine.VerifySeal(bc, b); err != nil {
			return fmt.Errorf("block %d: %w", i, err)
		}
	}
	return nil
}
