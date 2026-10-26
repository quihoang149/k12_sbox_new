package chain

import "encoding/binary"

// Minimal RLP encoder (Ethereum's serialization), enough for headers,
// transactions and accounts. Only encoding is needed: everything that is
// hashed is re-encoded from the struct.

// rlpBytes encodes a byte string.
func rlpBytes(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return []byte{b[0]}
	}
	return append(rlpHeader(0x80, len(b)), b...)
}

// rlpUint encodes an unsigned integer as its minimal big-endian bytes.
func rlpUint(u uint64) []byte {
	return rlpBytes(minimalBE(u))
}

// rlpList encodes a list whose items are already RLP-encoded.
func rlpList(items ...[]byte) []byte {
	n := 0
	for _, it := range items {
		n += len(it)
	}
	out := rlpHeader(0xc0, n)
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

func rlpHeader(offset byte, n int) []byte {
	if n < 56 {
		return []byte{offset + byte(n)}
	}
	lb := minimalBE(uint64(n))
	return append([]byte{offset + 55 + byte(len(lb))}, lb...)
}

func minimalBE(u uint64) []byte {
	if u == 0 {
		return nil
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], u)
	i := 0
	for buf[i] == 0 {
		i++
	}
	return buf[i:]
}

// Allocation-free variants used on hot paths (state root): they append to
// dst instead of returning fresh slices.

func appendRLPBytes(dst, b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return append(dst, b[0])
	}
	dst = appendRLPHeader(dst, 0x80, len(b))
	return append(dst, b...)
}

func appendRLPUint(dst []byte, u uint64) []byte {
	if u == 0 {
		return append(dst, 0x80)
	}
	if u < 0x80 {
		return append(dst, byte(u))
	}
	var buf [8]byte
	n := 0
	for v := u; v > 0; v >>= 8 {
		n++
	}
	for i := 0; i < n; i++ {
		buf[i] = byte(u >> (8 * (n - 1 - i)))
	}
	return append(append(dst, 0x80+byte(n)), buf[:n]...)
}

func appendRLPHeader(dst []byte, offset byte, n int) []byte {
	if n < 56 {
		return append(dst, offset+byte(n))
	}
	var buf [8]byte
	k := 0
	for v := n; v > 0; v >>= 8 {
		k++
	}
	for i := 0; i < k; i++ {
		buf[i] = byte(n >> (8 * (k - 1 - i)))
	}
	return append(append(dst, offset+55+byte(k)), buf[:k]...)
}

// appendRLPList appends a list whose already-encoded payload is in payload.
func appendRLPList(dst, payload []byte) []byte {
	return append(appendRLPHeader(dst, 0xc0, len(payload)), payload...)
}
