package linux

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PeerState is what the kernel reports about one configured peer.
type PeerState struct {
	PublicKey  string
	AllowedIPs []string
	// LatestHandshake is zero when the peer has never completed one. This is the
	// only trustworthy liveness signal: a tunnel is up when its peer handshook
	// recently, not when its process happens to be running.
	LatestHandshake time.Time
}

// IngressState is the observed configuration of the ingress interface.
type IngressState struct {
	Exists     bool
	PublicKey  string
	ListenPort uint16
	Peers      []PeerState
}

// unset is how the amneziawg tooling spells a missing value in dump output.
const unset = "(none)"

// ParseDump reads `awg show <interface> dump`.
//
// The first line describes the interface and carries the AmneziaWG obfuscation
// parameters, so it is wider than WireGuard's equivalent and its trailing fields are
// deliberately not interpreted. Every following line is a peer, in the same layout
// WireGuard uses: public key, preshared key, endpoint, allowed IPs, latest handshake,
// bytes received, bytes sent, keepalive.
func ParseDump(output string) (IngressState, error) {
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return IngressState{}, fmt.Errorf("empty dump output")
	}

	header := strings.Split(lines[0], "\t")
	if len(header) < 3 {
		return IngressState{}, fmt.Errorf("interface line has %d fields, want at least 3", len(header))
	}
	port, err := strconv.ParseUint(header[2], 10, 16)
	if err != nil {
		return IngressState{}, fmt.Errorf("invalid listen port %q: %w", header[2], err)
	}

	state := IngressState{Exists: true, PublicKey: header[1], ListenPort: uint16(port)}

	for index, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			return IngressState{}, fmt.Errorf("peer line %d has %d fields, want at least 5", index+1, len(fields))
		}

		peer := PeerState{PublicKey: fields[0]}
		if fields[3] != unset {
			peer.AllowedIPs = strings.Split(fields[3], ",")
		}
		handshake, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil {
			return IngressState{}, fmt.Errorf("peer %s: invalid handshake %q: %w", peer.PublicKey, fields[4], err)
		}
		if handshake > 0 {
			peer.LatestHandshake = time.Unix(handshake, 0).UTC()
		}
		state.Peers = append(state.Peers, peer)
	}

	return state, nil
}
