package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// keyFile is the private key of one thing the hub owns, kept on the machine.
//
// A key deliberately never travels in a revision: a revision is compiled on a
// workstation and copied around, while this stays where it is needed. The hub key
// and the fallback listener's key differ only in what generates them, what counts
// as valid, and what an operator has to be told when one is missing -- so those
// are the fields, and everything else is written once.
type keyFile struct {
	path string
	// noun names the key in messages, in the case a sentence starts with.
	noun string
	// missing tells an operator what to do about a key that is not there. It is
	// the whole of the error, because meeting it means they have just switched
	// something on and have no reason to know a second key exists.
	missing func(path string) string
	// clobbered says what replacing an existing key would cost.
	clobbered func(path string) string

	generate func() (private, public string, err error)
	validate func(key string) error
}

// read returns the key, checking that it is one this hub can actually use.
func (k keyFile) read() (string, error) {
	data, err := os.ReadFile(k.path)
	if os.IsNotExist(err) {
		return "", fmt.Errorf("%s", k.missing(k.path))
	}
	if err != nil {
		return "", fmt.Errorf("read %s key: %w", k.noun, err)
	}
	key := strings.TrimSpace(string(data))
	if err := k.validate(key); err != nil {
		return "", fmt.Errorf("%s key at %s is unusable: %w", k.noun, k.path, err)
	}
	return key, nil
}

// create writes a freshly generated key and refuses to overwrite one.
func (k keyFile) create() (publicKey string, err error) {
	private, public, err := k.generate()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return "", fmt.Errorf("create key directory: %w", err)
	}
	// O_EXCL makes "refuse to overwrite" atomic and correct. A Stat check first
	// races a concurrent writer, and a Stat error other than not-exist (EACCES,
	// say) would be read as "absent" and clobber a key that is in fact present.
	handle, err := os.OpenFile(k.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return "", fmt.Errorf("%s", k.clobbered(k.path))
		}
		return "", fmt.Errorf("write %s key: %w", k.noun, err)
	}
	// A write that fails takes the file with it. What O_EXCL left behind is empty
	// or half a key, and nothing here can tell that from a real one later: `read`
	// would call it unusable and `create` would refuse to replace it, leaving a hub
	// that can only be recovered by an operator who knows to delete the file. It is
	// ours -- created exclusively a line ago -- so removing it is safe.
	//
	// Synced for the same reason: this key is the one piece of hub state that
	// cannot be regenerated once anything depends on it, and a power loss between
	// the write and the flush would leave exactly the same empty file.
	if err := writeAndSync(handle, private+"\n"); err != nil {
		_ = os.Remove(k.path)
		return "", fmt.Errorf("write %s key: %w", k.noun, err)
	}
	return public, nil
}

// writeAndSync writes the whole of content, flushes it to the disk and closes the
// handle, reporting the first thing that went wrong.
func writeAndSync(handle *os.File, content string) error {
	if _, err := handle.WriteString(content); err != nil {
		_ = handle.Close()
		return err
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		return err
	}
	return handle.Close()
}
