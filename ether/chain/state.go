package chain

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
)

// Account is an externally owned account.
type Account struct {
	Nonce   uint64
	Balance uint64
}

// Validator is a PoS validator. Its key signs blocks and attestations; it is
// separate from account keys, like Ethereum's BLS validator keys.
type Validator struct {
	PubKey     []byte  // ed25519 public key (32 bytes)
	Withdrawal Address // where rewards are paid
	Stake      uint64
	Slashed    bool
}

// Active validators can propose and attest.
func (v *Validator) Active() bool { return !v.Slashed && v.Stake > 0 }

// StateDB is the world state: accounts plus the validator registry.
//
// Changes are journaled so a block can be applied in place and rolled back
// if it turns out to be invalid. This avoids copying the whole state for
// every block, so measured block times are dominated by real work (hashing,
// signatures) rather than memory copies.
type StateDB struct {
	accounts   map[Address]*Account
	validators []Validator
	journal    []journalEntry
	sorted     []Address // cached sorted address list; nil when stale
}

type journalEntry struct {
	isValidator bool
	addr        Address
	prev        Account
	existed     bool
	vidx        int
	prevV       Validator
}

func NewStateDB() *StateDB { return &StateDB{accounts: map[Address]*Account{}} }

// Copy returns an independent deep copy (journal not included).
func (s *StateDB) Copy() *StateDB {
	c := NewStateDB()
	for a, acc := range s.accounts {
		cp := *acc
		c.accounts[a] = &cp
	}
	c.validators = append([]Validator(nil), s.validators...)
	c.sorted = s.sorted // immutable once built
	return c
}

// Snapshot returns an id to pass to RevertTo.
func (s *StateDB) Snapshot() int { return len(s.journal) }

// RevertTo undoes every change made after the snapshot.
func (s *StateDB) RevertTo(id int) {
	for i := len(s.journal) - 1; i >= id; i-- {
		e := s.journal[i]
		switch {
		case e.isValidator:
			s.validators[e.vidx] = e.prevV
		case e.existed:
			*s.accounts[e.addr] = e.prev
		default:
			delete(s.accounts, e.addr)
			s.sorted = nil
		}
	}
	s.journal = s.journal[:id]
}

// Commit makes all journaled changes permanent.
func (s *StateDB) Commit() { s.journal = s.journal[:0] }

// touch returns a mutable account, journaling its previous value.
func (s *StateDB) touch(a Address) *Account {
	acc, ok := s.accounts[a]
	if !ok {
		acc = &Account{}
		s.accounts[a] = acc
		s.sorted = nil
		s.journal = append(s.journal, journalEntry{addr: a})
		return acc
	}
	s.journal = append(s.journal, journalEntry{addr: a, prev: *acc, existed: true})
	return acc
}

func (s *StateDB) touchValidator(i int) *Validator {
	s.journal = append(s.journal, journalEntry{isValidator: true, vidx: i, prevV: s.validators[i]})
	return &s.validators[i]
}

func (s *StateDB) Balance(a Address) uint64 {
	if acc, ok := s.accounts[a]; ok {
		return acc.Balance
	}
	return 0
}

func (s *StateDB) Nonce(a Address) uint64 {
	if acc, ok := s.accounts[a]; ok {
		return acc.Nonce
	}
	return 0
}

func (s *StateDB) AddBalance(a Address, v uint64) { s.touch(a).Balance += v }

// NumAccounts returns the number of accounts in the state.
func (s *StateDB) NumAccounts() int { return len(s.accounts) }

// Validators returns a read-only view of the registry.
func (s *StateDB) Validators() []Validator { return s.validators }

// AddValidator registers a validator (genesis only in this simulator).
func (s *StateDB) AddValidator(v Validator) {
	s.validators = append(s.validators, v)
}

// TotalActiveStake sums the stake of active validators.
func (s *StateDB) TotalActiveStake() (total uint64) {
	for i := range s.validators {
		if s.validators[i].Active() {
			total += s.validators[i].Stake
		}
	}
	return
}

func (s *StateDB) sortedAddrs() []Address {
	if s.sorted == nil {
		addrs := make([]Address, 0, len(s.accounts))
		for a := range s.accounts {
			addrs = append(addrs, a)
		}
		sort.Slice(addrs, func(i, j int) bool { return bytes.Compare(addrs[i][:], addrs[j][:]) < 0 })
		s.sorted = addrs
	}
	return s.sorted
}

// leaves returns the encoded state: accounts sorted by address, then
// validators by index. Tags 0/1 keep the two kinds apart. All leaves share
// one buffer, so computing a root does not allocate per account.
func (s *StateDB) leaves() [][]byte {
	addrs := s.sortedAddrs()
	n := len(addrs) + len(s.validators)
	buf := make([]byte, 0, len(addrs)*42+len(s.validators)*80)
	ends := make([]int, 0, n)
	var scratch [128]byte
	for _, a := range addrs {
		acc := s.accounts[a]
		p := appendRLPUint(scratch[:0], 0)
		p = appendRLPBytes(p, a[:])
		p = appendRLPUint(p, acc.Nonce)
		p = appendRLPUint(p, acc.Balance)
		buf = appendRLPList(buf, p)
		ends = append(ends, len(buf))
	}
	for i := range s.validators {
		v := &s.validators[i]
		slashed := uint64(0)
		if v.Slashed {
			slashed = 1
		}
		p := appendRLPUint(scratch[:0], 1)
		p = appendRLPUint(p, uint64(i))
		p = appendRLPBytes(p, v.PubKey)
		p = appendRLPBytes(p, v.Withdrawal[:])
		p = appendRLPUint(p, v.Stake)
		p = appendRLPUint(p, slashed)
		buf = appendRLPList(buf, p)
		ends = append(ends, len(buf))
	}
	out := make([][]byte, n)
	start := 0
	for i, e := range ends {
		out[i] = buf[start:e:e]
		start = e
	}
	return out
}

// Root is the state root committed in each block header. It is recomputed
// from scratch: 2n-1 hashes for n leaves. Real Ethereum clients update a
// Merkle-Patricia trie incrementally, but each touched path rehashes several
// ~500-byte branch nodes, so per-block hashing volume is of the same order.
func (s *StateDB) Root(h Hasher) Hash { return MerkleRoot(h, s.leaves()) }

var (
	ErrNonce        = errors.New("nonce mismatch")
	ErrInsufficient = errors.New("insufficient balance for value + gas")
	ErrIntrinsicGas = errors.New("gas limit below intrinsic gas")
	ErrChainID      = errors.New("wrong chain id")
)

// ApplyTransaction validates and executes tx, paying the fee to coinbase.
// It returns the gas used. On error the state is left untouched.
func (s *StateDB) ApplyTransaction(h Hasher, tx *Transaction, coinbase Address, chainID uint64) (uint64, error) {
	from, err := tx.Sender(h)
	return s.applyWithSender(tx, from, err, coinbase, chainID)
}

// applyWithSender executes tx whose signature was already verified
// (possibly in parallel) giving from / sigErr.
func (s *StateDB) applyWithSender(tx *Transaction, from Address, sigErr error, coinbase Address, chainID uint64) (uint64, error) {
	if tx.ChainID != chainID {
		return 0, ErrChainID
	}
	if sigErr != nil {
		return 0, sigErr
	}
	var nonce, balance uint64
	if a, ok := s.accounts[from]; ok {
		nonce, balance = a.Nonce, a.Balance
	}
	if nonce != tx.Nonce {
		return 0, fmt.Errorf("%w: have %d, tx %d", ErrNonce, nonce, tx.Nonce)
	}
	gas := tx.IntrinsicGas()
	if tx.GasLimit < gas {
		return 0, ErrIntrinsicGas
	}
	fee := gas * tx.GasPrice
	if tx.GasPrice != 0 && fee/tx.GasPrice != gas { // overflow
		return 0, ErrInsufficient
	}
	cost := tx.Value + fee
	if cost < tx.Value || balance < cost { // overflow or not enough funds
		return 0, ErrInsufficient
	}
	acc := s.touch(from)
	acc.Balance -= cost
	acc.Nonce++
	s.touch(tx.To).Balance += tx.Value
	s.touch(coinbase).Balance += fee
	return gas, nil
}
