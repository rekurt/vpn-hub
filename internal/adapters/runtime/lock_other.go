//go:build !unix

package runtime

// The hub only ever runs on Linux; this keeps the package buildable elsewhere.
func lockStateDir(string) (release func(), err error) {
	return func() {}, nil
}
