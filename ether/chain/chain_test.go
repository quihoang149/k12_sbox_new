package chain

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

var hashers = []Hasher{NewKeccakHasher(), NewK12Hasher(nil), NewK12SBoxHasher(nil)}

func TestRLPVectors(t *testing.T) {
	cases := []struct {
		got  []byte
		want string
	}{
		{rlpBytes([]byte("dog")), "83646f67"},
		{rlpList(rlpBytes([]byte("cat")), rlpBytes([]byte("dog"))), "c88363617483646f67"},
		{rlpBytes(nil), "80"},
		{rlpList(), "c0"},
		{rlpUint(0), "80"},
		{rlpUint(15), "0f"},
		{rlpUint(1024), "820400"},
		{rlpBytes([]byte("Lorem ipsum dolor sit amet, consectetur adipisicing elit")),
			"b838" + hex.EncodeToString([]byte("Lorem ipsum dolor sit amet, consectetur adipisicing elit"))},
	}
	for i, c := range cases {
		if hex.EncodeToString(c.got) != c.want {
			t.Errorf("case %d: got %x want %s", i, c.got, c.want)
		}
	}
}

// Ethereum's empty-list hash keccak256(rlp([])) is a well known constant
// (it is the "uncles hash" of every block without ommers).
func TestKeccakEmptyListHash(t *testing.T) {
	got := NewKeccakHasher().Sum(rlpList())
	want := "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("got %x", got)
	}
}

func TestMerkleProofs(t *testing.T) {
	for _, h := range hashers {
		for n := 1; n <= 17; n++ {
			leaves := make([][]byte, n)
			for i := range leaves {
				leaves[i] = []byte(fmt.Sprintf("leaf-%d", i))
			}
			root := MerkleRoot(h, leaves)
			for i := range leaves {
				p := MerkleProof(h, leaves, i)
				if !VerifyMerkleProof(h, root, leaves[i], p) {
					t.Fatalf("%s n=%d i=%d: valid proof rejected", h.Name(), n, i)
				}
				if VerifyMerkleProof(h, root, []byte("forged"), p) {
					t.Fatalf("%s n=%d i=%d: forged leaf accepted", h.Name(), n, i)
				}
			}
		}
	}
}

func TestSignatureAndAddress(t *testing.T) {
	for _, h := range hashers {
		k, _ := GenerateKey()
		tx := &Transaction{Nonce: 3, GasPrice: 1, GasLimit: 21000, Value: 5, ChainID: 1}
		if err := tx.Sign(h, k); err != nil {
			t.Fatal(err)
		}
		from, err := tx.Sender(h)
		if err != nil || from != k.Address(h) {
			t.Fatalf("%s: sender mismatch: %v", h.Name(), err)
		}
		tx.Value = 6
		if _, err := tx.Sender(h); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("%s: modified tx still verifies", h.Name())
		}
	}
}

// A signature made under one hash function must not verify under the other:
// the two chains are incompatible by construction.
func TestCrossHashIncompatible(t *testing.T) {
	k, _ := GenerateKey()
	tx := &Transaction{GasLimit: 21000, ChainID: 1}
	tx.Sign(NewKeccakHasher(), k)
	if _, err := tx.Sender(NewK12Hasher(nil)); err == nil {
		t.Fatal("keccak-signed tx verified under K12")
	}
}

func newTestChain(t testing.TB, h Hasher) (*Blockchain, []*Key, []Address) {
	keys := make([]*Key, 3)
	addrs := make([]Address, 3)
	alloc := map[Address]uint64{}
	for i := range keys {
		keys[i], _ = GenerateKey()
		addrs[i] = keys[i].Address(h)
		alloc[addrs[i]] = 1_000_000
	}
	// Difficulty high enough that a tampered header passes PoW with prob ~1e-5.
	return NewBlockchain(h, DefaultConfig(), NewPoWEngine(1<<16, 0), alloc), keys, addrs
}

func TestChainLifecycle(t *testing.T) {
	for _, h := range hashers {
		bc, keys, addrs := newTestChain(t, h)
		follower := bc.Clone()
		tx := &Transaction{Nonce: 0, GasPrice: 2, GasLimit: 21000, To: addrs[1], Value: 100, ChainID: bc.Cfg.ChainID}
		tx.Sign(h, keys[0])
		bad := &Transaction{Nonce: 7, GasPrice: 1, GasLimit: 21000, To: addrs[1], Value: 1, ChainID: bc.Cfg.ChainID}
		bad.Sign(h, keys[0])

		blk, st, err := bc.ProduceBlock([]*Transaction{tx, bad}, addrs[2])
		if err != nil {
			t.Fatalf("%s: %v", h.Name(), err)
		}
		if st.Included != 1 || st.Dropped != 1 {
			t.Fatalf("%s: included=%d dropped=%d", h.Name(), st.Included, st.Dropped)
		}
		reward := bc.Engine.(*PoWEngine).Reward
		s := bc.State()
		if s.Balance(addrs[0]) != 1_000_000-100-42000 || s.Balance(addrs[1]) != 1_000_100 ||
			s.Balance(addrs[2]) != 1_000_000+42000+reward || s.Nonce(addrs[0]) != 1 {
			t.Fatalf("%s: wrong balances after block", h.Name())
		}
		if !CheckPoW(h, &blk.Header) {
			t.Fatalf("%s: PoW not valid", h.Name())
		}
		if err := follower.InsertBlock(blk); err != nil {
			t.Fatalf("%s: follower rejected block: %v", h.Name(), err)
		}
		if follower.State().Root(h) != bc.State().Root(h) {
			t.Fatal("follower state diverged")
		}
		if err := bc.Verify(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInsertRejectsTampering(t *testing.T) {
	for _, h := range hashers {
		cases := map[string]struct {
			mutate func(b *Block)
			reseal bool
			want   error
		}{
			"state root": {func(b *Block) { b.Header.StateRoot[0] ^= 1 }, true, ErrBadStateRoot},
			"tx root":    {func(b *Block) { b.Txs = nil }, true, ErrBadTxRoot},
			"parent":     {func(b *Block) { b.Header.ParentHash[0] ^= 1 }, false, ErrUnknownParent},
			"difficulty": {func(b *Block) { b.Header.Difficulty = 1 }, false, ErrBadDifficulty},
			"nonce":      {func(b *Block) { b.Header.Time++ }, false, ErrBadPoW},
		}
		for name, c := range cases {
			bc, keys, addrs := newTestChain(t, h)
			follower := bc.Clone()
			tx := &Transaction{GasPrice: 1, GasLimit: 21000, To: addrs[1], Value: 1, ChainID: bc.Cfg.ChainID}
			tx.Sign(h, keys[0])
			blk, _, err := bc.ProduceBlock([]*Transaction{tx}, addrs[2])
			if err != nil {
				t.Fatal(err)
			}
			before := follower.State().Root(h)
			c.mutate(blk)
			if c.reseal {
				Seal(h, &blk.Header, nil) // re-mine so PoW is not what fails
			}
			if err := follower.InsertBlock(blk); !errors.Is(err, c.want) {
				t.Errorf("%s/%s: got %v want %v", h.Name(), name, err, c.want)
			}
			if follower.State().Root(h) != before || follower.Len() != 1 {
				t.Errorf("%s/%s: rejected block changed the state", h.Name(), name)
			}
		}
	}
}

func TestPoWRejectsBadNonce(t *testing.T) {
	h := NewK12Hasher(nil)
	hd := &Header{Number: 1, Difficulty: 1 << 20}
	Seal(h, hd, nil)
	if !CheckPoW(h, hd) {
		t.Fatal("sealed header fails PoW")
	}
	hd.Nonce++
	// With difficulty 2^20 the next nonce is valid with prob ~1e-6.
	if CheckPoW(h, hd) {
		t.Skip("astronomically unlucky: next nonce also valid")
	}
}

// Difficulty must rise when blocks come too fast and fall when too slow.
func TestDifficultyAdjustment(t *testing.T) {
	e := NewPoWEngine(1000, 100)
	parent := &Header{Number: 5, Difficulty: 1000, Time: 10_000}
	if d := e.CalcDifficulty(parent, 10_100); d != 1000 {
		t.Errorf("on target: %d", d)
	}
	if d := e.CalcDifficulty(parent, 10_010); d != 1225 {
		t.Errorf("too fast should raise: %d", d)
	}
	if d := e.CalcDifficulty(parent, 10_200); d != 750 {
		t.Errorf("too slow should lower: %d", d)
	}
	if d := e.CalcDifficulty(parent, 99_000); d != 500 {
		t.Errorf("drop is clamped to 1/2: %d", d)
	}
}

func TestStateJournal(t *testing.T) {
	h := NewK12Hasher(nil)
	s := NewStateDB()
	var a, b Address
	b[0] = 1
	s.AddBalance(a, 10)
	s.AddValidator(Validator{Stake: 5})
	s.Commit()
	root := s.Root(h)
	snap := s.Snapshot()
	s.AddBalance(a, 1)
	s.AddBalance(b, 7) // new account
	s.touchValidator(0).Slashed = true
	if s.Root(h) == root {
		t.Fatal("root unchanged after writes")
	}
	s.RevertTo(snap)
	if s.Root(h) != root || s.NumAccounts() != 1 || s.Validators()[0].Slashed {
		t.Fatal("revert did not restore state")
	}
}
