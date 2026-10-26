//go:build !amd64 || appengine || gccgo

package k12

func keccakF1600(a *[25]uint64, nr int) { keccakF1600Generic(a, nr) }
