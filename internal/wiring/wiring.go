// Package wiring assembles the application layer from its adapters.
//
// Every delivery -- hubctl, the agent, the Telegram bot -- needs the same services
// built the same way; a second copy of this assembly is how two entry points drift
// into configuring the same hub differently.
package wiring

import (
	"path/filepath"

	configadapter "vpn-hub/internal/adapters/config"
	"vpn-hub/internal/adapters/linux"
	runtimeadapter "vpn-hub/internal/adapters/runtime"
	"vpn-hub/internal/application"
	"vpn-hub/internal/ports"
)

// ConfigRepository reads a directory layout when given one and a single file
// otherwise, so the example and the tests need no directory.
func ConfigRepository(path string) ports.ConfigRepository {
	if configadapter.IsDirectory(path) {
		return configadapter.DirectoryRepository{Path: path}
	}
	return configadapter.ViperRepository{Path: path}
}

// Service assembles the operator-facing side: validate, compile, save, probe.
func Service(configPath, stateDir string) application.Service {
	return application.Service{
		ConfigRepository: ConfigRepository(configPath),
		RevisionStore:    runtimeadapter.FileRevisionStore{StateDir: stateDir},
		// Probing from the host would measure the host's own connectivity, which is
		// the path the tunnel exists to avoid.
		HealthChecker: linux.HealthChecker{RuntimeDir: linux.DefaultRuntimeDir},
	}
}

// RealityKeyPath names the fallback listener's key, beside the configuration it
// belongs to. Derived rather than given a flag of its own: the agent, the bot and
// hubctl all need it, and three flags is three chances for one of them to look at a
// different file and quietly disagree about which devices can connect.
func RealityKeyPath(configDir string) string {
	return filepath.Join(configDir, "reality.key")
}

// RealityKey is the store hubctl and the bot read to issue client links.
func RealityKey(configDir string) linux.RealityKeyFile {
	return linux.RealityKeyFile{Path: RealityKeyPath(configDir)}
}

// Reconciler wires the host-facing adapters. Everything it drives only formats or
// executes; the decisions live in the application layer.
func Reconciler(keyPath, runtimeDir, configDir string) ports.Reconciler {
	return application.HostReconciler{
		Firewall:      linux.NFTables{RuntimeDir: runtimeDir},
		Ingress:       linux.Ingress{SecretsDir: runtimeDir},
		Egress:        linux.Egress{SecretsDir: runtimeDir},
		DNS:           linux.Dnsmasq{ConfigDir: runtimeDir},
		TunnelConfigs: linux.TunnelConfigFiles{Dir: configDir, Secrets: configadapter.SOPSSecretStore{}},
		Host:          linux.NetConf{},
		ServerKey:     linux.ServerKeyFile{Path: keyPath},
		Reality:       linux.RealityIngress{SecretsDir: runtimeDir},
		RealityKey:    RealityKey(configDir),
	}
}
