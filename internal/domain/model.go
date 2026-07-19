package domain

import (
	"encoding/json"
	"time"
)

type TunnelType string

const (
	TunnelWireGuard TunnelType = "wireguard"
	TunnelOpenVPN   TunnelType = "openvpn"
	TunnelXray      TunnelType = "xray"
	TunnelAmneziaWG TunnelType = "amneziawg"
)

type TunnelRole string

const (
	RolePrivateNetwork TunnelRole = "private-network"
	RoleEgress         TunnelRole = "egress"
)

type SourceKind string

const (
	SourceConfig       SourceKind = "config"
	SourceXrayURI      SourceKind = "xray-uri"
	SourceXrayJSON     SourceKind = "xray-json"
	SourceSubscription SourceKind = "subscription"
)

type Hub struct {
	Endpoint        string            `mapstructure:"endpoint" json:"endpoint"`
	ServerPublicKey string            `mapstructure:"server_public_key" json:"server_public_key"`
	ClientCIDR      string            `mapstructure:"client_cidr" json:"client_cidr"`
	DNSAddress      string            `mapstructure:"dns_address" json:"dns_address"`
	AWGInterface    map[string]string `mapstructure:"awg_interface" json:"awg_interface,omitempty"`
}

type TunnelSource struct {
	Kind  SourceKind `mapstructure:"kind" json:"kind"`
	Value string     `mapstructure:"value" json:"value"`
}

// MarshalJSON keeps credential-bearing sources out of the persisted revision.
//
// A `config` source names a file on the host and is safe — and useful — to see. An
// Xray URI or a subscription URL embeds a UUID or token, and a revision is written
// to disk and read back by anything that can open the state directory.
func (s TunnelSource) MarshalJSON() ([]byte, error) {
	type plain TunnelSource // avoids recursing into this method
	if s.Kind == SourceXrayURI || s.Kind == SourceSubscription {
		return json.Marshal(plain{Kind: s.Kind, Value: "[redacted]"})
	}
	return json.Marshal(plain(s))
}

type HealthCheck struct {
	TCPAddress string `mapstructure:"tcp_address" json:"tcp_address,omitempty"`
	HTTPSURL   string `mapstructure:"https_url" json:"https_url,omitempty"`
	DNSName    string `mapstructure:"dns_name" json:"dns_name,omitempty"`
}

type Tunnel struct {
	ID   string     `mapstructure:"id" json:"id"`
	Type TunnelType `mapstructure:"type" json:"type"`
	Role TunnelRole `mapstructure:"role" json:"role"`
	// Enabled defaults to true when absent. A disabled tunnel is dropped from the
	// revision entirely rather than built and left unused, so "off" means off.
	Enabled        *bool        `mapstructure:"enabled" json:"enabled,omitempty"`
	Source         TunnelSource `mapstructure:"source" json:"source"`
	Routes         []string     `mapstructure:"routes" json:"routes,omitempty"`
	DNSServers     []string     `mapstructure:"dns_servers" json:"dns_servers,omitempty"`
	DNSZones       []string     `mapstructure:"dns_zones" json:"dns_zones,omitempty"`
	AllowedDevices []string     `mapstructure:"allowed_devices" json:"allowed_devices,omitempty"`
	Health         HealthCheck  `mapstructure:"health" json:"health,omitempty"`
}

func (t Tunnel) IsEnabled() bool { return t.Enabled == nil || *t.Enabled }

// DeviceProfile is the pre-M5 shape, kept solely so validation can recognise it and
// say what replaced it. Profiles existed to pick an egress per connection; the hub
// now decides by destination, so a device has one address and one default egress.
type DeviceProfile struct {
	ID               string `mapstructure:"id"`
	Egress           string `mapstructure:"egress"`
	Address          string `mapstructure:"address"`
	ClientPublicKey  string `mapstructure:"client_public_key"`
	ClientPrivateKey string `mapstructure:"client_private_key"`
}

type Device struct {
	ID      string `mapstructure:"id" json:"id"`
	Address string `mapstructure:"address" json:"address"`
	// PublicKey is all the hub needs; the private half stays with the device.
	PublicKey string `mapstructure:"public_key" json:"public_key"`
	// Egress names the tunnel carrying this device's internet traffic. Private
	// networks are reached in addition to it, chosen by destination.
	Egress string `mapstructure:"egress" json:"egress"`

	Profiles []DeviceProfile `mapstructure:"profiles" json:"-"`
}

type Config struct {
	Hub     Hub      `mapstructure:"hub" json:"hub"`
	Devices []Device `mapstructure:"devices" json:"devices"`
	Tunnels []Tunnel `mapstructure:"tunnels" json:"tunnels"`
}

type DeployedDevice struct {
	ID        string `json:"id"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	Egress    string `json:"egress"`
}

type DesiredState struct {
	Revision    string           `json:"revision"`
	GeneratedAt time.Time        `json:"generated_at"`
	Hub         Hub              `json:"hub"`
	Devices     []DeployedDevice `json:"devices"`
	Tunnels     []Tunnel         `json:"tunnels"`
}

type OperationKind string

const (
	OpCreate OperationKind = "create"
	OpUpdate OperationKind = "update"
	OpDelete OperationKind = "delete"
)

// ResourceRef identifies what an operation acts on.
type ResourceRef struct {
	Type string `json:"type"` // "nftables" | "ingress" | "peer"
	ID   string `json:"id"`
}

// Operation is one difference between the desired and the observed host.
//
// It carries no command string. An earlier version did, describing shell that was
// never run, which let the agent report work it had not done. Reason states what
// differs, not what will be typed.
type Operation struct {
	Kind     OperationKind `json:"kind"`
	Resource ResourceRef   `json:"resource"`
	Reason   string        `json:"reason"`
}

func (o Operation) String() string {
	return string(o.Kind) + " " + o.Resource.Type + "/" + o.Resource.ID + ": " + o.Reason
}

type HealthStatus string

const (
	// HealthUnknown means nothing was actually measured. A tunnel with no probes
	// configured is unknown, never healthy: claiming health without evidence is the
	// most dangerous answer a VPN can give, because the operator stops looking.
	HealthUnknown   HealthStatus = "unknown"
	HealthHealthy   HealthStatus = "healthy"
	HealthUnhealthy HealthStatus = "unhealthy"
)

type TunnelHealth struct {
	TunnelID  string       `json:"tunnel_id"`
	Status    HealthStatus `json:"status"`
	CheckedAt time.Time    `json:"checked_at"`
	Reason    string       `json:"reason,omitempty"`
}
