package mint

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/bbockelm/golang-htcondor/droppriv"
)

// KeySize is the length of a signing key this package creates: 64 random
// bytes, as HTCondor's Condor_Auth_Passwd::create_signing_key generates for
// the collector's POOL key and an AP collector's named key.
const KeySize = 64

// openExclusive creates the key file; a variable so tests can substitute a
// file that fails to write.
var openExclusive = func(path string) (keyFile, error) {
	f, err := droppriv.OpenFileAsRoot(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	return f, nil
}

type keyFile interface {
	Write(p []byte) (int, error)
	Sync() error
	Truncate(size int64) error
	Close() error
}

// scramble applies HTCondor's simple_scramble, an XOR with 0xdeadbeef
// repeated, which is how a password or signing key is stored on disk. It is
// its own inverse.
func scramble(in []byte) []byte {
	deadbeef := [4]byte{0xde, 0xad, 0xbe, 0xef}
	out := make([]byte, len(in))
	for i := range in {
		out[i] = in[i] ^ deadbeef[i%len(deadbeef)]
	}
	return out
}

// KeyFile is the path of the signing key: KeyID in KeyDir.
func (m *Minter) KeyFile() (string, error) {
	if m.KeyID == "" || strings.ContainsAny(m.KeyID, `/\`) || strings.Contains(m.KeyID, "..") {
		return "", fmt.Errorf("mint: invalid signing key name %q", m.KeyID)
	}
	return filepath.Join(m.KeyDir, m.KeyID), nil
}

// CreateKeyIfMissing creates the signing key file when it does not exist,
// the way an HTCondor collector creates its token signing key at startup and
// on every reconfig. The file is opened as root with O_CREAT|O_EXCL, mode
// 0600, so an existing key (or anything else at that path, a symlink
// included) is never replaced; that case returns false and no error. The key
// is KeySize bytes from crypto/rand, written scrambled exactly as HTCondor's
// write_binary_password_file writes it, so the collector reading the same
// file accepts the tokens minted with it.
//
// With KeyDir unset (no SEC_PASSWORD_DIRECTORY) there is nowhere to create
// the key and nothing is done, as in HTCondor.
//
// When the write fails after the file was created, the file is truncated to
// empty rather than left holding part of a key; the minter refuses an empty
// key, and the file must be removed for a new one to be created.
func (m *Minter) CreateKeyIfMissing() (bool, error) {
	if m.KeyDir == "" {
		return false, nil
	}
	path, err := m.KeyFile()
	if err != nil {
		return false, err
	}
	f, err := openExclusive(path)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("mint: creating signing key %s: %w", path, err)
	}
	key := make([]byte, KeySize)
	_, werr := rand.Read(key)
	if werr == nil {
		_, werr = f.Write(scramble(key))
	}
	if werr == nil {
		werr = f.Sync()
	}
	if werr != nil {
		_ = f.Truncate(0)
		_ = f.Close()
		return false, fmt.Errorf("mint: writing signing key %s (remove the empty file so it is created again): %w", path, werr)
	}
	if err := f.Close(); err != nil {
		return true, fmt.Errorf("mint: closing signing key %s: %w", path, err)
	}
	return true, nil
}
