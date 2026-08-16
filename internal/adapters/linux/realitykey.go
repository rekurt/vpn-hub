package linux

import (
	"context"
	"fmt"

	"vpn-hub/internal/domain"
)

// RealityKeyFile holds the fallback listener's private key, beside the hub key and
// for the same reason: it belongs to the machine, not to a revision that gets
// compiled on a workstation and copied around.
type RealityKeyFile struct {
	Path string
}

func (s RealityKeyFile) file() keyFile {
	path := s.Path
	if path == "" {
		path = DefaultConfigDir + "/reality.key"
	}
	return keyFile{
		path: path, noun: "REALITY",
		missing: func(path string) string {
			return fmt.Sprintf("no REALITY key at %s: run `hubctl keygen --reality` on the hub, "+
				"or turn hub.fallback.reality off", path)
		},
		clobbered: func(path string) string {
			return fmt.Sprintf("%s already exists; replacing the REALITY key "+
				"would invalidate every issued link", path)
		},
		generate: domain.GenerateRealityKeyPair,
		validate: domain.ValidateRealityKey,
	}
}

// PrivateKey reads the key. A missing key is reported as the thing to do about it:
// the fallback is off by default, so an operator meeting this error has just turned
// it on and has no reason to know a second key exists.
func (s RealityKeyFile) PrivateKey(_ context.Context) (string, error) {
	return s.file().read()
}

// Create writes a freshly generated key and refuses to overwrite one, exactly as
// the hub key does: replacing it invalidates every vless:// link already issued.
func (s RealityKeyFile) Create() (publicKey string, err error) {
	return s.file().create()
}
