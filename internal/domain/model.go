package domain

import "time"

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

type HealthCheck struct {
	TCPAddress string `mapstructure:"tcp_address" json:"tcp_address,omitempty"`
	HTTPSURL   string `mapstructure:"https_url" json:"https_url,omitempty"`
	DNSName    string `mapstructure:"dns_name" json:"dns_name,omitempty"`
}

type Tunnel struct {
	ID             string       `mapstructure:"id" json:"id"`
	Type           TunnelType   `mapstructure:"type" json:"type"`
	Role           TunnelRole   `mapstructure:"role" json:"role"`
	Source         TunnelSource `mapstructure:"source" json:"source"`
	Routes         []string     `mapstructure:"routes" json:"routes,omitempty"`
	DNSServers     []string     `mapstructure:"dns_servers" json:"dns_servers,omitempty"`
	DNSZones       []string     `mapstructure:"dns_zones" json:"dns_zones,omitempty"`
	AllowedDevices []string     `mapstructure:"allowed_devices" json:"allowed_devices,omitempty"`
	Health         HealthCheck  `mapstructure:"health" json:"health,omitempty"`
}

type DeviceProfile struct {
	ID               string `mapstructure:"id" json:"id"`
	Egress           string `mapstructure:"egress" json:"egress"`
	Address          string `mapstructure:"address" json:"address"`
	ClientPublicKey  string `mapstructure:"client_public_key" json:"client_public_key,omitempty"`
	ClientPrivateKey string `mapstructure:"client_private_key" json:"-"`
}

type Device struct {
	ID       string          `mapstructure:"id" json:"id"`
	Profiles []DeviceProfile `mapstructure:"profiles" json:"profiles"`
}

type Config struct {
	Hub     Hub      `mapstructure:"hub" json:"hub"`
	Devices []Device `mapstructure:"devices" json:"devices"`
	Tunnels []Tunnel `mapstructure:"tunnels" json:"tunnels"`
}

type DeployedProfile struct {
	ID              string `json:"id"`
	Egress          string `json:"egress"`
	Address         string `json:"address"`
	ClientPublicKey string `json:"client_public_key"`
}

type DeployedDevice struct {
	ID       string            `json:"id"`
	Profiles []DeployedProfile `json:"profiles"`
}

type DesiredState struct {
	Revision    string           `json:"revision"`
	GeneratedAt time.Time        `json:"generated_at"`
	Hub         Hub              `json:"hub"`
	Devices     []DeployedDevice `json:"devices"`
	Tunnels     []Tunnel         `json:"tunnels"`
}

type Operation struct {
	Kind        string `json:"kind"`
	Resource    string `json:"resource"`
	Description string `json:"description"`
	Command     string `json:"command"`
}

type TunnelHealth struct {
	TunnelID  string    `json:"tunnel_id"`
	Healthy   bool      `json:"healthy"`
	CheckedAt time.Time `json:"checked_at"`
	Reason    string    `json:"reason,omitempty"`
}
