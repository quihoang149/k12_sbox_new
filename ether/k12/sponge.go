// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Derived from golang.org/x/crypto/sha3/sha3.go.
//
// Changes for this project:
//   - configurable number of rounds (12 for K12, 24 for Keccak-256);
//   - the buffer is tracked with an integer offset instead of a slice that
//     points back into the struct. The self-referencing slice made every
//     hasher escape to the heap (~1 KiB allocation per hash), which dominated
//     the cost of hashing short inputs and skewed K12-vs-Keccak comparisons.
//     A plain struct copy is now a correct clone.
package k12

// spongeDirection indicates the direction bytes are flowing through the sponge.
type spongeDirection int

const (
	// spongeAbsorbing indicates that the sponge is absorbing input.
	spongeAbsorbing spongeDirection = iota
	// spongeSqueezing indicates that the sponge is being squeezed.
	spongeSqueezing
)

// maxRate is the largest rate used (K12 / SHAKE128: 168 bytes).
const maxRate = 168

type state struct {
	a       [25]uint64    // Keccak-f[1600] state
	storage [maxRate]byte // input buffer while absorbing, output block while squeezing
	n       int           // absorbing: bytes buffered; squeezing: bytes already read
	rate    int           // bytes of state used per block
	dsbyte  byte          // domain separation bits + first padding bit
	rounds  int           // Keccak-f rounds; 0 means 12
	perm    permKind      // which permutation to use
	state   spongeDirection
}

// permKind selects the permutation used by a sponge.
type permKind uint8

const (
	permKeccak   permKind = iota // Keccak-f[1600]: assembly on amd64, else pure Go
	permKeccakGo                 // Keccak-f[1600], always pure Go (fair baseline)
	permSBox                     // Keccak-f[1600] with the proposed S-box instead of chi (pure Go)
)

// f applies the selected permutation.
func (d *state) f() {
	switch d.perm {
	case permSBox:
		keccakF1600SBox(&d.a, d.nr())
	case permKeccakGo:
		keccakF1600Generic(&d.a, d.nr())
	default:
		keccakF1600(&d.a, d.nr())
	}
}

func (d *state) nr() int {
	if d.rounds == 0 {
		return 12
	}
	return d.rounds
}

// BlockSize returns the rate of the sponge.
func (d *state) BlockSize() int { return d.rate }

// Reset zeroes the permutation state and returns to absorbing.
// rate, dsbyte and rounds are kept.
func (d *state) Reset() {
	d.a = [25]uint64{}
	d.n = 0
	d.state = spongeAbsorbing
}

// absorbBlock xors one full block into the state and permutes.
func (d *state) absorbBlock(block []byte) {
	xorIn(d, block)
	d.f()
}

// squeezeBlock permutes and exposes a fresh output block.
func (d *state) squeezeBlock() {
	d.f()
	copyOut(d, d.storage[:d.rate])
	d.n = 0
}

// padAndPermute appends dsbyte, applies the 10*1 padding rule, absorbs the
// final block and switches to squeezing.
func (d *state) padAndPermute() {
	// There is always at least one free byte: a full buffer is absorbed
	// immediately by Write.
	d.storage[d.n] = d.dsbyte
	for i := d.n + 1; i < d.rate; i++ {
		d.storage[i] = 0
	}
	d.storage[d.rate-1] ^= 0x80
	d.absorbBlock(d.storage[:d.rate])

	d.state = spongeSqueezing
	copyOut(d, d.storage[:d.rate])
	d.n = 0
}

// Write absorbs more data into the sponge.
func (d *state) Write(p []byte) (written int, err error) {
	if d.state != spongeAbsorbing {
		panic("sha3: write to sponge after read")
	}
	written = len(p)
	for len(p) > 0 {
		if d.n == 0 && len(p) >= d.rate {
			// Fast path: absorb straight from the input.
			d.absorbBlock(p[:d.rate])
			p = p[d.rate:]
			continue
		}
		c := copy(d.storage[d.n:d.rate], p)
		d.n += c
		p = p[c:]
		if d.n == d.rate {
			d.absorbBlock(d.storage[:d.rate])
			d.n = 0
		}
	}
	return
}

// Read squeezes an arbitrary number of bytes from the sponge.
func (d *state) Read(out []byte) (n int, err error) {
	if d.state == spongeAbsorbing {
		d.padAndPermute()
	}
	n = len(out)
	for len(out) > 0 {
		c := copy(out, d.storage[d.n:d.rate])
		d.n += c
		out = out[c:]
		if d.n == d.rate {
			d.squeezeBlock()
		}
	}
	return
}
