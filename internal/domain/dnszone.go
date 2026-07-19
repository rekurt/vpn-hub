package domain

import (
	"fmt"
	"strings"
)

// ValidateDNSZone rejects a zone name that could not be written into a resolver's
// configuration file as a single directive.
//
// The resolver is configured by generating text, one directive per line, and a zone
// is interpolated into two of them. A value containing a newline therefore writes
// directives of its own, and dnsmasq offers some powerful ones: `address=/#/1.2.3.4`
// answers every name in existence with one address. The zone is operator-supplied,
// but so is everything else that gets pasted in from a provider's instructions.
func ValidateDNSZone(zone string) error {
	if zone == "" {
		return fmt.Errorf("the DNS zone is empty")
	}
	if len(zone) > 253 {
		return fmt.Errorf("DNS zone %q is longer than a domain name may be", zone)
	}
	for _, label := range strings.Split(zone, ".") {
		if label == "" {
			return fmt.Errorf("DNS zone %q has an empty label", zone)
		}
		for _, char := range label {
			switch {
			case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z':
			case char >= '0' && char <= '9':
			case char == '-' || char == '_':
			default:
				return fmt.Errorf("DNS zone %q contains %q, which is not allowed in a domain name", zone, char)
			}
		}
	}
	return nil
}
