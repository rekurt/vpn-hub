package domain

import "strings"

// awgParameters maps each AmneziaWG obfuscation parameter to the spelling the client
// expects. The lookup is by lower-case name because Viper folds map keys to lower
// case while decoding YAML, so `Jc:` in the configuration file arrives here as `jc`
// no matter how it was written.
var awgParameters = map[string]string{
	"jc": "Jc", "jmin": "Jmin", "jmax": "Jmax",
	"s1": "S1", "s2": "S2",
	"h1": "H1", "h2": "H2", "h3": "H3", "h4": "H4",
}

// CanonicalAWGParameter returns the canonical spelling of an AmneziaWG parameter and
// whether it is one at all.
func CanonicalAWGParameter(name string) (string, bool) {
	canonical, known := awgParameters[strings.ToLower(name)]
	return canonical, known
}
