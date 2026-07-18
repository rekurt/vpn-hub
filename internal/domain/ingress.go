package domain

// PeerSpec is one client profile as the ingress interface should hold it.
type PeerSpec struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
}

// IngressSpec describes the AmneziaWG interface the hub presents to clients.
//
// It lives in the domain rather than in the adapter because deciding which peers
// exist and what they may claim is policy; turning that into `awg` invocations is
// mechanism.
type IngressSpec struct {
	Interface  string `json:"interface"`
	Address    string `json:"address"`
	ListenPort uint16 `json:"listen_port"`
	// PrivateKey never leaves the host and is deliberately not serialised.
	PrivateKey string `json:"-"`
	// Parameters are the obfuscation knobs, already validated and canonicalised.
	Parameters map[string]string `json:"parameters,omitempty"`
	// Peers is ordered deterministically so repeated reconciles are comparable.
	Peers []PeerSpec `json:"peers"`
}
