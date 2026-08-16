package application

import (
	"fmt"
	"sort"
	"strings"

	"vpn-hub/internal/domain"
)

// Diff reports how the observed host differs from what a revision asks for.
//
// It is a pure function, which is the point: deciding what counts as drift is the
// part worth testing exhaustively, and it needs no host to do so. The adapters are
// left with formatting and execution.
//
// firewallRevision is the fingerprint the desired ruleset would carry;
// realityRevision the one a listener running the revision would report.
func Diff(spec domain.IngressSpec, firewallRevision, realityRevision string, observed domain.ObservedState) []domain.Operation {
	var operations []domain.Operation

	switch {
	case observed.FirewallRevision == "":
		operations = append(operations, domain.Operation{
			Kind:     domain.OpCreate,
			Resource: domain.ResourceRef{Type: "nftables", ID: "inet vpn_hub"},
			Reason:   "the table is absent; the ruleset was flushed or the host has not converged since boot",
		})
	case observed.FirewallRevision != firewallRevision:
		operations = append(operations, domain.Operation{
			Kind:     domain.OpUpdate,
			Resource: domain.ResourceRef{Type: "nftables", ID: "inet vpn_hub"},
			Reason: fmt.Sprintf("the loaded ruleset is revision %s, the revision asks for %s",
				observed.FirewallRevision, firewallRevision),
		})
	}

	operations = append(operations, diffIngress(spec, observed.Ingress)...)
	operations = append(operations, diffPeers(spec, observed.Ingress)...)
	operations = append(operations, diffReality(realityRevision, observed.RealityFingerprint)...)
	return operations
}

// diffReality reports a fallback listener that is not the one the revision asks
// for. Both fingerprints are empty on a hub that does not use the fallback, which
// is agreement rather than absence.
func diffReality(wanted, running string) []domain.Operation {
	if wanted == running {
		return nil
	}
	reference := domain.ResourceRef{Type: "reality", ID: "vpn-hub-reality"}
	switch {
	case wanted == "":
		return []domain.Operation{{
			Kind: domain.OpDelete, Resource: reference,
			Reason: "a fallback listener is running and the revision does not ask for one",
		}}
	case running == "":
		return []domain.Operation{{
			Kind: domain.OpCreate, Resource: reference,
			Reason: "the revision asks for a fallback listener and none is running",
		}}
	default:
		return []domain.Operation{{
			Kind: domain.OpUpdate, Resource: reference,
			Reason: "the running fallback listener was started from a different configuration",
		}}
	}
}

func diffIngress(spec domain.IngressSpec, observed domain.IngressObservation) []domain.Operation {
	if !observed.Exists {
		return []domain.Operation{{
			Kind:     domain.OpCreate,
			Resource: domain.ResourceRef{Type: "ingress", ID: spec.Interface},
			Reason:   "the interface does not exist",
		}}
	}

	var reasons []string
	// An empty observed key means the interface exists but carries no key yet.
	if observed.PublicKey != "" {
		if derived, err := domain.PublicKeyFromPrivate(spec.PrivateKey); err == nil && derived != observed.PublicKey {
			reasons = append(reasons, "the interface carries a different key")
		}
	}
	if observed.ListenPort != 0 && observed.ListenPort != spec.ListenPort {
		reasons = append(reasons, fmt.Sprintf("it listens on %d, the revision asks for %d",
			observed.ListenPort, spec.ListenPort))
	}
	if len(reasons) == 0 {
		return nil
	}
	return []domain.Operation{{
		Kind:     domain.OpUpdate,
		Resource: domain.ResourceRef{Type: "ingress", ID: spec.Interface},
		Reason:   strings.Join(reasons, "; "),
	}}
}

// diffPeers is where revocation becomes visible: a peer the revision no longer names
// has to go, or the device keeps handshaking.
func diffPeers(spec domain.IngressSpec, observed domain.IngressObservation) []domain.Operation {
	wanted := make(map[string]domain.PeerSpec, len(spec.Peers))
	for _, peer := range spec.Peers {
		wanted[peer.PublicKey] = peer
	}
	present := make(map[string]domain.PeerObservation, len(observed.Peers))
	for _, peer := range observed.Peers {
		present[peer.PublicKey] = peer
	}

	var operations []domain.Operation
	for _, key := range sortedPeerKeys(wanted) {
		live, exists := present[key]
		if !exists {
			operations = append(operations, domain.Operation{
				Kind:     domain.OpCreate,
				Resource: domain.ResourceRef{Type: "peer", ID: shortKey(key)},
				Reason:   "the revision names this peer and the interface does not carry it",
			})
			continue
		}
		if !sameStrings(live.AllowedIPs, wanted[key].AllowedIPs) {
			operations = append(operations, domain.Operation{
				Kind:     domain.OpUpdate,
				Resource: domain.ResourceRef{Type: "peer", ID: shortKey(key)},
				Reason: fmt.Sprintf("allowed addresses are %s, the revision asks for %s",
					join(live.AllowedIPs), join(wanted[key].AllowedIPs)),
			})
		}
	}

	for _, key := range sortedObservationKeys(present) {
		if _, keep := wanted[key]; !keep {
			operations = append(operations, domain.Operation{
				Kind:     domain.OpDelete,
				Resource: domain.ResourceRef{Type: "peer", ID: shortKey(key)},
				Reason:   "the revision no longer names this peer",
			})
		}
	}
	return operations
}

// shortKey keeps a peer identifiable in a log line without printing a full key.
func shortKey(publicKey string) string {
	if len(publicKey) <= 12 {
		return publicKey
	}
	return publicKey[:12] + "…"
}

func join(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ",")
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	first := append([]string(nil), a...)
	second := append([]string(nil), b...)
	sort.Strings(first)
	sort.Strings(second)
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func sortedPeerKeys(values map[string]domain.PeerSpec) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedObservationKeys(values map[string]domain.PeerObservation) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
