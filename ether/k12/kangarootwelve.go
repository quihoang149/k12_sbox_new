//
// Do whatever you want with this file
// Author: David Wong
// Contact: https://www.cryptologie.net/contact
//

package k12

import (
	"encoding/binary"
)

//
// Objects & Constants
//

const (
	maxChunk = 8192 // size of a K12 chunk
)

// firstChunkSuffix is appended after the first chunk in tree mode: 110^62.
var firstChunkSuffix = [8]byte{0x03}

// treeSuffix ends the final node in tree mode.
var treeSuffix = [2]byte{0xff, 0xff}

// main K12 object with two distincts sponge states
type treeState struct {
	customString    []byte
	phase           spongeDirection // to avoid absorbing when we're already in the squeezing phase
	state           state           // the main state
	numChunk        int             // needed for logic and padding
	currentChunk    state           // not for the first chunk
	currentWritten  int             // needed to know if we switch to a different chunk
	tempChunkOutput [256 / 8]byte   // needed to truncate a chunk's output
}

//
// High level API
//

// The constructor requires a customization string.
// It can be: empty, the name of your application, etc...
// Note: I dit not follow golang.org/x/crypto/sha3/shake.go and did not defined a new interface here
func NewK12(customString []byte) treeState { return newK12(customString, permKeccak) }

// NewK12SBox is K12 whose Keccak-p permutation uses the proposed S-box in
// place of chi. Tree mode, padding and round count are unchanged. Its
// outputs differ from standard K12 (no official test vectors apply).
func NewK12SBox(customString []byte) treeState { return newK12(customString, permSBox) }

func newK12(customString []byte, p permKind) treeState {
	return treeState{
		customString: customString,
		state:        state{rate: 168, perm: p},
		currentChunk: state{rate: 168, dsbyte: 0x0b, perm: p},
	}
}

// A single-use function for
// Note: I dit not follow golang.org/x/crypto/sha3/shake.go and reversed the `data` and `hash` arguments
func K12Sum(customString, data, hash []byte) {
	h := NewK12(customString)
	h.Write(data)
	h.Read(hash)
}

// Allows you to read while preserving the original state
// The sponge no longer holds slices into itself, so a struct copy is a
// complete, independent clone (the original shared buffers with the source).
func (t *treeState) Clone() *treeState {
	ret := *t
	return &ret
}

// Allows you to re-use a K12 instance.
func (t *treeState) Reset() {
	t.state.Reset()
	t.currentChunk.Reset()
	// Fix: the original forgot these, so a reused instance hashed garbage.
	t.state.dsbyte = 0
	t.numChunk = 0
	t.currentWritten = 0
	t.phase = spongeAbsorbing
}

// Write absorbs more data into the hash's state.
// It doesn't produce an error at the moment.
func (t *treeState) Write(p []byte) (written int, err error) {

	if t.phase != spongeAbsorbing {
		panic("cannot write after read")
	}
	//
	written = len(p)

	// absorbing 🍟
	for len(p) > 0 {
		// we reached the end of the chunk → we create a new chunk
		if t.currentWritten == maxChunk {

			if t.numChunk == 0 {
				// pad the main state
				t.state.Write(firstChunkSuffix[:]) // 110^62
			} else {
				// truncate + write the chunk
				t.currentChunk.Read(t.tempChunkOutput[:]) // padding is in dsByte of t.currentChunk
				t.state.Write(t.tempChunkOutput[:])
				t.currentChunk.Reset()
			}

			// on to the new chunk!
			t.currentWritten = 0
			t.numChunk++
		}

		// we figure out how much data we can write
		todo := maxChunk - t.currentWritten
		if todo > len(p) {
			todo = len(p)
		}

		var written int
		if t.numChunk == 0 {
			written, _ = t.state.Write(p[:todo])
		} else {
			written, _ = t.currentChunk.Write(p[:todo])
		}

		t.currentWritten += written

		// what's left for the loop
		p = p[todo:]

	}

	return
}

// Reads data. This can be used infinitely (pretty much)
func (t *treeState) Read(out []byte) (n int, err error) {
	// finish absorbing → padding
	if t.phase == spongeAbsorbing {

		// custom string
		t.Write(t.customString)
		t.Write(right_encode(uint64(len(t.customString))))

		// padding
		if t.numChunk == 0 {
			// one chunk
			t.state.dsbyte = 0x07 // 11|10 0000
		} else {
			// many chunks
			t.currentChunk.Read(t.tempChunkOutput[:]) // padding is in dsByte of t.currentChunk
			t.state.Write(t.tempChunkOutput[:])

			t.state.Write(right_encode(uint64(t.numChunk)))
			t.state.Write(treeSuffix[:])
			t.state.dsbyte = 0x06 // 01|10 0000
		}
		t.phase = spongeSqueezing
	}

	// rely on the sponge's function to read
	n, err = t.state.Read(out)

	//
	return
}

//
// Helpers
//

// Encodes the length of a value. It is used in the final padding of K12
func right_encode(value uint64) []byte {
	var input [9]byte
	var offset int
	if value == 0 {
		offset = 8
	} else {
		binary.BigEndian.PutUint64(input[0:], value)
		for offset = 0; offset < 9; offset++ {
			if input[offset] != 0 {
				break
			}
		}
	}
	input[8] = byte(8 - offset)
	return input[offset:]
}
