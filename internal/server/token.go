package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// The owner token (PROTOCOL.md §6.1) is computed, never stored:
//
//	T   = "igt1_" + base64url(kid ‖ epoch ‖ mac), no padding
//	mac = HMAC-SHA-256(K_kid, "irongall-token-v1" ‖ H ‖ kid ‖ epoch)
//
// with kid a u8 naming the server key, epoch the box's u32 counter (big
// endian) and H the address's 32 raw bytes. The DB holds only the epoch.

const (
	tokenPrefix = "igt1_"
	tokenMACTag = "irongall-token-v1" //nolint:gosec // a MAC domain tag, not a credential
	tokenLen    = 1 + 4 + sha256.Size
)

// Token errors: a token that is not ours, and one that is ours but stale.
var (
	errBadToken   = errors.New("not a valid token")
	errStaleToken = errors.New("the token is stale")
)

// Keys are the server's token keys. Mint uses Current; Check accepts any key
// it holds.
type Keys struct {
	Current uint8
	keys    map[uint8][]byte
}

// NewDevKeys returns one random key, kid 1, as the dev server uses: tokens
// die with the process, as does everything else it holds.
func NewDevKeys() (*Keys, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return &Keys{Current: 1, keys: map[uint8][]byte{1: k}}, nil
}

// LoadKeys reads the server's token keys (PROTOCOL.md §6.1) from a file
// readable by its owner only: one key per line, "<kid> <key>", the key as
// standard base64 of 32 random bytes; blank lines and lines starting # are
// skipped. Tokens are minted with the highest kid, and checked with any.
func LoadKeys(path string) (*Keys, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: the token keys are readable by others (mode %04o): chmod 600", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path) //nolint:gosec // the keys file the operator named
	if err != nil {
		return nil, err
	}
	k := &Keys{keys: map[uint8][]byte{}}
	for i, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		kid, err := strconv.ParseUint(f[0], 10, 8)
		if len(f) != 2 || err != nil {
			return nil, fmt.Errorf("%s:%d: not \"<kid> <base64 key>\"", path, i+1)
		}
		key, err := base64.StdEncoding.Strict().DecodeString(f[1])
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("%s:%d: the key is not base64 of 32 bytes", path, i+1)
		}
		if _, dup := k.keys[uint8(kid)]; dup {
			return nil, fmt.Errorf("%s:%d: kid %d twice", path, i+1, kid)
		}
		k.keys[uint8(kid)] = key
		k.Current = max(k.Current, uint8(kid))
	}
	if len(k.keys) == 0 {
		return nil, fmt.Errorf("%s: no keys", path)
	}
	return k, nil
}

func tokenMAC(key []byte, a protocol.Address, kid uint8, epoch uint32) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(tokenMACTag))
	m.Write(a[:])
	m.Write([]byte{kid})
	m.Write(binary.BigEndian.AppendUint32(nil, epoch))
	return m.Sum(nil)
}

// Mint returns box a's token at epoch, with the current key.
func (k *Keys) Mint(a protocol.Address, epoch uint32) string {
	raw := make([]byte, 0, tokenLen)
	raw = append(raw, k.Current)
	raw = binary.BigEndian.AppendUint32(raw, epoch)
	raw = append(raw, tokenMAC(k.keys[k.Current], a, k.Current, epoch)...)
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

// Check validates a token for box a at its current epoch, in constant time
// over the MAC. A token for another epoch is errStaleToken.
func (k *Keys) Check(a protocol.Address, epoch uint32, token string) error {
	e, err := k.verify(a, token)
	if err != nil {
		return err
	}
	if e != epoch {
		return errStaleToken
	}
	return nil
}

// verify checks that this server minted token for box a, at whatever epoch
// it names, and returns that epoch.
func (k *Keys) verify(a protocol.Address, token string) (uint32, error) {
	s, ok := strings.CutPrefix(token, tokenPrefix)
	if !ok {
		return 0, errBadToken
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) != tokenLen {
		return 0, errBadToken
	}
	kid, e := raw[0], binary.BigEndian.Uint32(raw[1:5])
	key, ok := k.keys[kid]
	if !ok {
		return 0, errBadToken
	}
	if !hmac.Equal(raw[5:], tokenMAC(key, a, kid, e)) {
		return 0, errBadToken
	}
	return e, nil
}

// An adopt key (PROTOCOL.md §6.5) lets a box join an account. It is
// computed, as the token is; the account's table holds only its state:
//
//	K   = "iga1_" + base64url(kid ‖ id ‖ n ‖ account ‖ mac), no padding
//	mac = HMAC-SHA-256(K_kid, "irongall-adopt-v1" ‖ kid ‖ id ‖ n ‖ account)
//
// with id the key's 16 random bytes and n the account id's length in bytes.
const (
	adoptPrefix = "iga1_"
	adoptMACTag = "irongall-adopt-v1" //nolint:gosec // a MAC domain tag, not a credential
)

func adoptMAC(key []byte, kid uint8, id [16]byte, account string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(adoptMACTag))
	m.Write([]byte{kid})
	m.Write(id[:])
	m.Write([]byte{byte(len(account))}) //nolint:gosec // an account id is at most 32 bytes
	m.Write([]byte(account))
	return m.Sum(nil)
}

// MintAdopt returns adopt key id of account, with the current key.
func (k *Keys) MintAdopt(account string, id [16]byte) string {
	raw := append([]byte{k.Current}, id[:]...)
	raw = append(raw, byte(len(account))) //nolint:gosec // an account id is at most 32 bytes
	raw = append(raw, account...)
	raw = append(raw, adoptMAC(k.keys[k.Current], k.Current, id, account)...)
	return adoptPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

// VerifyAdopt checks that this server minted an adopt key, and returns the
// account and the key's id. Whether it is still good is the account table's
// to say.
func (k *Keys) VerifyAdopt(s string) (string, [16]byte, error) {
	var id [16]byte
	s, ok := strings.CutPrefix(s, adoptPrefix)
	if !ok {
		return "", id, errBadToken
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) < 1+16+1+sha256.Size {
		return "", id, errBadToken
	}
	kid, n := raw[0], int(raw[17])
	if len(raw) != 1+16+1+n+sha256.Size {
		return "", id, errBadToken
	}
	copy(id[:], raw[1:17])
	account := string(raw[18 : 18+n])
	key, ok := k.keys[kid]
	if !ok || !validAccountID(account) {
		return "", id, errBadToken
	}
	if !hmac.Equal(raw[18+n:], adoptMAC(key, kid, id, account)) {
		return "", id, errBadToken
	}
	return account, id, nil
}
