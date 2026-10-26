package chain

// Engine is the consensus algorithm. The chain itself (transactions, state,
// Merkle roots) is identical under PoW and PoS; only these hooks differ,
// mirroring go-ethereum's consensus.Engine.
type Engine interface {
	Name() string

	// InitGenesis sets consensus fields of the genesis header and state.
	InitGenesis(h Hasher, g *Header, st *StateDB)

	// Prepare fills the consensus fields of a new block on top of the head
	// (block producer only). The body (attestations, ...) may be filled too.
	Prepare(bc *Blockchain, b *Block) error

	// Finalize applies consensus state changes: rewards, slashing.
	// Must be deterministic: every node runs it.
	Finalize(bc *Blockchain, st *StateDB, b *Block)

	// Seal completes the block: PoW nonce search, or PoS proposer signature.
	Seal(bc *Blockchain, b *Block) (SealInfo, error)

	// VerifyConsensus checks consensus fields and the seal of b against its
	// parent, using the head state (every node, before executing b).
	VerifyConsensus(bc *Blockchain, parent, b *Block) error

	// VerifySeal is a light check used when re-verifying a stored chain.
	VerifySeal(bc *Blockchain, b *Block) error

	// Committed runs after b becomes the head (e.g. finality bookkeeping).
	Committed(bc *Blockchain, b *Block)
}

// SealInfo reports the cost of sealing.
type SealInfo struct {
	Attempts uint64 // PoW hashes tried; 0 for PoS
}
