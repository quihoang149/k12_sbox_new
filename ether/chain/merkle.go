package chain

// Binary Merkle tree with domain separation between leaves and inner nodes
// (prefix 0x00 / 0x01), which blocks second-preimage tricks that confuse a
// leaf with an inner node. An odd node at the end of a level is promoted
// unchanged (no duplication, avoiding Bitcoin's CVE-2012-2459 ambiguity).

var (
	leafPrefix = []byte{0x00}
	nodePrefix = []byte{0x01}
)

// MerkleRoot computes the root over the given leaf data.
// The root of an empty list is H("").
func MerkleRoot(h Hasher, leaves [][]byte) Hash {
	if len(leaves) == 0 {
		return h.Sum()
	}
	level := make([]Hash, len(leaves))
	for i, l := range leaves {
		level[i] = h.Sum(leafPrefix, l)
	}
	// Reduce in place: level[i/2] <- H(level[i], level[i+1]).
	for n := len(level); n > 1; n = (n + 1) / 2 {
		for i := 0; i < n; i += 2 {
			if i+1 == n {
				level[i/2] = level[i]
			} else {
				level[i/2] = h.Sum(nodePrefix, level[i][:], level[i+1][:])
			}
		}
	}
	return level[0]
}

func nextLevel(h Hasher, level []Hash) []Hash {
	next := make([]Hash, 0, (len(level)+1)/2)
	for i := 0; i < len(level); i += 2 {
		if i+1 == len(level) {
			next = append(next, level[i])
			continue
		}
		next = append(next, h.Sum(nodePrefix, level[i][:], level[i+1][:]))
	}
	return next
}

// ProofStep is one sibling on the path from a leaf to the root.
type ProofStep struct {
	Sibling Hash
	Left    bool // sibling is on the left
}

// MerkleProof returns the inclusion proof for leaves[index].
func MerkleProof(h Hasher, leaves [][]byte, index int) []ProofStep {
	if index < 0 || index >= len(leaves) {
		return nil
	}
	level := make([]Hash, len(leaves))
	for i, l := range leaves {
		level[i] = h.Sum(leafPrefix, l)
	}
	var proof []ProofStep
	for len(level) > 1 {
		sib := index ^ 1
		if sib < len(level) {
			proof = append(proof, ProofStep{Sibling: level[sib], Left: sib < index})
		}
		level = nextLevel(h, level)
		index /= 2
	}
	return proof
}

// VerifyMerkleProof checks that leaf is included under root.
func VerifyMerkleProof(h Hasher, root Hash, leaf []byte, proof []ProofStep) bool {
	cur := h.Sum(leafPrefix, leaf)
	for _, s := range proof {
		if s.Left {
			cur = h.Sum(nodePrefix, s.Sibling[:], cur[:])
		} else {
			cur = h.Sum(nodePrefix, cur[:], s.Sibling[:])
		}
	}
	return cur == root
}
