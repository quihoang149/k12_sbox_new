package chain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
)

// Gas schedule (Ethereum values for a plain transfer and calldata).
const (
	TxGas            = 21000
	TxDataNonZeroGas = 16
	TxDataZeroGas    = 4
)

// Key is an account key pair.
type Key struct {
	priv *ecdsa.PrivateKey
}

func GenerateKey() (*Key, error) {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Key{priv: p}, nil
}

// PubBytes returns X||Y (64 bytes), like Ethereum's uncompressed key
// without the 0x04 prefix.
func (k *Key) PubBytes() []byte { return pubBytes(&k.priv.PublicKey) }

// Address is the last 20 bytes of H(X||Y), exactly as in Ethereum.
func (k *Key) Address(h Hasher) Address { return PubToAddress(h, k.PubBytes()) }

func pubBytes(p *ecdsa.PublicKey) []byte {
	out := make([]byte, 64)
	p.X.FillBytes(out[:32])
	p.Y.FillBytes(out[32:])
	return out
}

func PubToAddress(h Hasher, pub []byte) (a Address) {
	d := h.Sum(pub)
	copy(a[:], d[12:])
	return
}

// Transaction is a value transfer, laid out like a legacy Ethereum tx.
type Transaction struct {
	Nonce    uint64
	GasPrice uint64
	GasLimit uint64
	To       Address
	Value    uint64
	Data     []byte
	ChainID  uint64

	// Signature. PubKey is carried explicitly because P-256 has no public
	// key recovery in the Go standard library (Ethereum recovers it from v).
	PubKey []byte // 64 bytes X||Y
	R, S   []byte // 32 bytes each
}

// unsignedRLP is the EIP-155 style payload that gets signed.
func (tx *Transaction) unsignedRLP() []byte {
	return rlpList(
		rlpUint(tx.Nonce), rlpUint(tx.GasPrice), rlpUint(tx.GasLimit),
		rlpBytes(tx.To[:]), rlpUint(tx.Value), rlpBytes(tx.Data),
		rlpUint(tx.ChainID), rlpUint(0), rlpUint(0),
	)
}

// RLP is the full encoding including the signature.
func (tx *Transaction) RLP() []byte {
	return rlpList(
		rlpUint(tx.Nonce), rlpUint(tx.GasPrice), rlpUint(tx.GasLimit),
		rlpBytes(tx.To[:]), rlpUint(tx.Value), rlpBytes(tx.Data),
		rlpUint(tx.ChainID), rlpBytes(tx.PubKey), rlpBytes(tx.R), rlpBytes(tx.S),
	)
}

// SigHash is the digest that is signed.
func (tx *Transaction) SigHash(h Hasher) Hash { return h.Sum(tx.unsignedRLP()) }

// Hash is the transaction id.
func (tx *Transaction) Hash(h Hasher) Hash { return h.Sum(tx.RLP()) }

// IntrinsicGas is the gas the transaction costs before any execution.
func (tx *Transaction) IntrinsicGas() uint64 {
	g := uint64(TxGas)
	for _, b := range tx.Data {
		if b == 0 {
			g += TxDataZeroGas
		} else {
			g += TxDataNonZeroGas
		}
	}
	return g
}

// Sign fills in the signature fields.
func (tx *Transaction) Sign(h Hasher, k *Key) error {
	d := tx.SigHash(h)
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, d[:])
	if err != nil {
		return err
	}
	tx.PubKey = k.PubBytes()
	tx.R = r.FillBytes(make([]byte, 32))
	tx.S = s.FillBytes(make([]byte, 32))
	return nil
}

var ErrBadSignature = errors.New("invalid transaction signature")

// Sender verifies the signature and returns the sender address.
func (tx *Transaction) Sender(h Hasher) (Address, error) {
	if len(tx.PubKey) != 64 || len(tx.R) != 32 || len(tx.S) != 32 {
		return Address{}, ErrBadSignature
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(tx.PubKey[:32]),
		Y:     new(big.Int).SetBytes(tx.PubKey[32:]),
	}
	d := tx.SigHash(h)
	if !ecdsa.Verify(pub, d[:], new(big.Int).SetBytes(tx.R), new(big.Int).SetBytes(tx.S)) {
		return Address{}, ErrBadSignature
	}
	return PubToAddress(h, tx.PubKey), nil
}
