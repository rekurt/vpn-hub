package domain

// ProxyReality carries the REALITY handshake parameters.
type ProxyReality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
}

// ProxyTLS describes how the proxy connection is disguised.
type ProxyTLS struct {
	Enabled bool `json:"enabled"`
	// ServerName is what the handshake claims to be talking to.
	ServerName string `json:"server_name,omitempty"`
	// Fingerprint mimics a browser's TLS signature.
	Fingerprint string       `json:"fingerprint,omitempty"`
	Reality     ProxyReality `json:"reality,omitempty"`
}

// ProxyTransport is the stream the protocol runs over.
type ProxyTransport struct {
	// Type is empty for plain TCP, otherwise "ws", "grpc" or "httpupgrade".
	Type        string `json:"type,omitempty"`
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
}

// ProxyTunnel is an upstream reached by a proxy protocol rather than by a kernel
// tunnel. It is what a `vless://` link describes.
type ProxyTunnel struct {
	Protocol string `json:"protocol"`
	Server   string `json:"server"`
	Port     uint16 `json:"port"`
	// UUID authenticates the hub to the provider and is deliberately not serialised:
	// a revision is written to disk and read back by anything that can open the state
	// directory.
	UUID      string         `json:"-"`
	Flow      string         `json:"flow,omitempty"`
	TLS       ProxyTLS       `json:"tls"`
	Transport ProxyTransport `json:"transport,omitempty"`
}
