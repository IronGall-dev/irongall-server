package crypto

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// age ssh-ed25519 stanza tag = first 4 bytes of SHA-256 of the SSH wire-format public key (51 bytes).
var wire = append([]byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"), make([]byte, 32)...)
var gotTag = []byte{1, 2, 3, 4}

// Worst case: recompute the mailbox's tag on every send instead of caching it.
func BenchmarkSSHTagCheck(b *testing.B) {
	for i := 0; i < b.N; i++ {
		h := sha256.Sum256(wire)
		_ = bytes.Equal(h[:4], gotTag)
	}
}
