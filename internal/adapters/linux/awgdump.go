package linux

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"vpn-hub/internal/domain"
)

// unset is how the amneziawg tooling spells a missing value in dump output.
const unset = "(none)"

// ParseDump reads `awg show <interface> dump`.
//
// The first line describes the interface and carries the AmneziaWG obfuscation
// parameters, so it is wider than WireGuard's equivalent and its trailing fields are
// deliberately not interpreted. Every following line is a peer, in the same layout
// WireGuard uses: public key, preshared key, endpoint, allowed IPs, latest handshake,
// bytes received, bytes sent, keepalive.
func ParseDump(output string) (domain.IngressObservation, error) {
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return domain.IngressObservation{}, fmt.Errorf("empty dump output")
	}

	header := strings.Split(lines[0], "\t")
	if len(header) < 3 {
		return domain.IngressObservation{}, fmt.Errorf("interface line has %d fields, want at least 3", len(header))
	}
	port, err := strconv.ParseUint(header[2], 10, 16)
	if err != nil {
		return domain.IngressObservation{}, fmt.Errorf("invalid listen port %q: %w", header[2], err)
	}

	state := domain.IngressObservation{Exists: true, PublicKey: header[1], ListenPort: uint16(port)}

	for index, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			return domain.IngressObservation{}, fmt.Errorf("peer line %d has %d fields, want at least 5", index+1, len(fields))
		}

		peer := domain.PeerObservation{PublicKey: fields[0]}
		if fields[2] != unset {
			peer.Endpoint = fields[2]
		}
		if fields[3] != unset {
			peer.AllowedIPs = strings.Split(fields[3], ",")
		}
		handshake, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil {
			return domain.IngressObservation{}, fmt.Errorf("peer %s: invalid handshake %q: %w", peer.PublicKey, fields[4], err)
		}
		if handshake > 0 {
			peer.LatestHandshake = time.Unix(handshake, 0).UTC()
		}
		// Traffic counters answer "does this device actually use the hub"; a line
		// short enough to lack them still describes a valid peer.
		if len(fields) >= 7 {
			peer.RxBytes, _ = strconv.ParseUint(fields[5], 10, 64)
			peer.TxBytes, _ = strconv.ParseUint(fields[6], 10, 64)
		}
		state.Peers = append(state.Peers, peer)
	}

	return state, nil
}
