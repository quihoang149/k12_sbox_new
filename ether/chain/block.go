package chain

import "encoding/binary"

// Header mirrors the important fields of an Ethereum header. PoW uses
// Difficulty/Nonce; PoS uses Slot/ProposerIndex/RandaoMix. Unused fields
// stay zero.
type Header struct {
	ParentHash Hash
	Coinbase   Address // PoW: miner; PoS: proposer's withdrawal address
	StateRoot  Hash
	TxRoot     Hash
	ConsRoot   Hash // Merkle root of consensus messages (attestations, slashings)
	Number     uint64
	GasLimit   uint64
	GasUsed    uint64
	Time       uint64 // milliseconds

	// PoW
	Difficulty uint64
	Nonce      uint64

	// PoS
	Slot          uint64
	ProposerIndex uint64
	RandaoMix     Hash
}

func (hd *Header) fieldsRLP(withNonce bool) []byte {
	items := [][]byte{
		rlpBytes(hd.ParentHash[:]), rlpBytes(hd.Coinbase[:]),
		rlpBytes(hd.StateRoot[:]), rlpBytes(hd.TxRoot[:]), rlpBytes(hd.ConsRoot[:]),
		rlpUint(hd.Number), rlpUint(hd.GasLimit), rlpUint(hd.GasUsed),
		rlpUint(hd.Time), rlpUint(hd.Difficulty),
		rlpUint(hd.Slot), rlpUint(hd.ProposerIndex), rlpBytes(hd.RandaoMix[:]),
	}
	if withNonce {
		items = append(items, rlpUint(hd.Nonce))
	}
	return rlpList(items...)
}

// SealHash is the header hash without the PoW nonce (what miners work on).
func (hd *Header) SealHash(h Hasher) Hash { return h.Sum(hd.fieldsRLP(false)) }

// Hash is the block hash.
func (hd *Header) Hash(h Hasher) Hash { return h.Sum(hd.fieldsRLP(true)) }

// Block is a header plus its body.
type Block struct {
	Header Header
	Txs    []*Transaction

	// PoS body
	RandaoReveal []byte             // proposer's signature over the slot
	Attestations []Attestation      // votes for the parent block
	Slashings    []SlashingEvidence // proof that a proposer double-signed
	Signature    []byte             // proposer's signature over the block hash
}

func (b *Block) Hash(h Hasher) Hash { return b.Header.Hash(h) }

// TxRoot is the Merkle root of the RLP-encoded transactions.
func TxRoot(h Hasher, txs []*Transaction) Hash {
	leaves := make([][]byte, len(txs))
	for i, tx := range txs {
		leaves[i] = tx.RLP()
	}
	return MerkleRoot(h, leaves)
}

// ConsensusRoot is the Merkle root over attestations and slashing evidence.
func ConsensusRoot(h Hasher, b *Block) Hash {
	leaves := make([][]byte, 0, len(b.Attestations)+len(b.Slashings))
	for i := range b.Attestations {
		leaves = append(leaves, b.Attestations[i].RLP())
	}
	for i := range b.Slashings {
		leaves = append(leaves, b.Slashings[i].RLP())
	}
	return MerkleRoot(h, leaves)
}

func u64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}
