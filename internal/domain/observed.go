package domain

import "time"

// PeerObservation is what the kernel reports about one configured peer.
type PeerObservation struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	// LatestHandshake is zero when the peer has never completed one.
	LatestHandshake time.Time `json:"latest_handshake,omitempty"`
	// Endpoint is where the peer last spoke from; empty until it connects.
	Endpoint string `json:"endpoint,omitempty"`
	// RxBytes and TxBytes count since the interface came up, from the hub's side:
	// Rx is what the device sent.
	RxBytes uint64 `json:"rx_bytes,omitempty"`
	TxBytes uint64 `json:"tx_bytes,omitempty"`
}

// IngressObservation is the live state of the interface clients connect to.
type IngressObservation struct {
	Exists     bool              `json:"exists"`
	PublicKey  string            `json:"public_key,omitempty"`
	ListenPort uint16            `json:"listen_port,omitempty"`
	Peers      []PeerObservation `json:"peers,omitempty"`
}

// ObservedState is what the host actually looks like, as opposed to what a revision
// says it should. Without it the agent cannot tell convergence from repetition, and
// nothing can report drift.
type ObservedState struct {
	ObservedAt time.Time          `json:"observed_at"`
	Ingress    IngressObservation `json:"ingress"`
	// FirewallRevision is the fingerprint carried by the live nftables table. It is
	// empty when the table is absent, which is the common shape of drift: something
	// flushed the ruleset, or the host rebooted before the agent ran.
	FirewallRevision string `json:"firewall_revision,omitempty"`
	// RealityFingerprint is what the running fallback listener was started from,
	// empty when none runs. A hub with the fallback off leaves this empty and
	// expects it: it is only drift when the revision asks for a listener.
	RealityFingerprint string `json:"reality_fingerprint,omitempty"`
}
