// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (!amd64 && !386 && !ppc64le) || appengine
// +build !amd64,!386,!ppc64le appengine

package k12

func xorIn(d *state, buf []byte)   { xorInGeneric(d, buf) }
func copyOut(d *state, buf []byte) { copyOutGeneric(d, buf) }

const xorImplementationUnaligned = "generic"
