package domain

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Validate rejects probe targets that cannot be handed to a command safely.
//
// These three fields are the only place in a tunnel's configuration whose value is
// passed to a process as an argument, and `hubctl test tunnel` runs that process as
// root. A configuration is usually written by the operator, but "usually" is the
// wrong standard for a field that is routinely copied out of a provider's snippet
// or somebody else's repository -- and `hubctl test` is exactly the command reached
// for after pasting one. So the shapes are constrained here, once, rather than
// trusted at each call site.
func (h HealthCheck) Validate() error {
	if h.TCPAddress != "" {
		host, port, err := net.SplitHostPort(h.TCPAddress)
		if err != nil {
			return fmt.Errorf("tcp_address %q must be host:port: %w", h.TCPAddress, err)
		}
		// SplitHostPort splits; it does not judge. In the bracketed form it accepts
		// any bytes at all, so what it returns still has to be checked.
		if err := validateProbeHost(host); err != nil {
			return fmt.Errorf("tcp_address: %w", err)
		}
		if number, err := strconv.ParseUint(port, 10, 16); err != nil || number == 0 {
			return fmt.Errorf("tcp_address: %q is not a port number", port)
		}
	}

	if h.HTTPSURL != "" {
		// url.Parse already rejects ASCII control characters, but not spaces or shell
		// metacharacters in the path or query. Only the hostname was being checked, so
		// the rest of the URL was the one probe value left unconstrained. Reject any
		// whitespace in the whole URL: it closes the "https://ok/ -o /etc/passwd" shape
		// this field's threat model means to exclude, at no cost to real probe URLs.
		if strings.ContainsAny(h.HTTPSURL, " \t\r\n") {
			return fmt.Errorf("https_url %q must not contain whitespace", h.HTTPSURL)
		}
		parsed, err := url.Parse(h.HTTPSURL)
		if err != nil {
			return fmt.Errorf("https_url %q: %w", h.HTTPSURL, err)
		}
		// A probe that is allowed to be plain HTTP proves reachability while saying
		// nothing about whether the tunnel carries traffic intact.
		if parsed.Scheme != "https" {
			return fmt.Errorf("https_url %q must use https", h.HTTPSURL)
		}
		if err := validateProbeHost(parsed.Hostname()); err != nil {
			return fmt.Errorf("https_url: %w", err)
		}
	}

	if h.DNSName != "" {
		if err := validateProbeHost(h.DNSName); err != nil {
			return fmt.Errorf("dns_name: %w", err)
		}
	}
	return nil
}

// validateProbeHost accepts an IP address or a hostname, and nothing else.
//
// The character set is the restriction that matters: a value reaching a command
// line must not be able to end one argument and begin another, name a file, or --
// where a shell is involved anywhere downstream -- be read as syntax.
func validateProbeHost(host string) error {
	if host == "" {
		return fmt.Errorf("the host is empty")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if strings.HasPrefix(host, "-") {
		return fmt.Errorf("%q starts with a dash, which a command would read as a flag", host)
	}
	if len(host) > 253 {
		return fmt.Errorf("%q is longer than a domain name may be", host)
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" {
			return fmt.Errorf("%q has an empty label", host)
		}
		for _, char := range label {
			switch {
			case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z':
			case char >= '0' && char <= '9':
			case char == '-' || char == '_':
			default:
				return fmt.Errorf("%q contains %q, which is not allowed in a host name", host, char)
			}
		}
	}
	return nil
}
