// Package wiring assembles the application layer from its adapters.
//
// Every delivery -- hubctl, the agent, the Telegram bot -- needs the same services
// built the same way; a second copy of this assembly is how two entry points drift
// into configuring the same hub differently.
package wiring

import (
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
	}
}
