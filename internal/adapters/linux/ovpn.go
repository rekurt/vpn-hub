package linux

import (
	"fmt"
	"strconv"
	"strings"

	"vpn-hub/internal/domain"
)

// inlineBlocks are the certificate and key sections providers embed in a .ovpn file
// rather than shipping alongside it.
var inlineBlocks = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true,
	"auth-user-pass": true,
}

var externalFileDirectives = map[string]bool{
	"auth-user-pass":       true,
	"http-proxy-user-pass": true,
	"askpass":              true,
	"pkcs12":               true,
	"crl-verify":           true,
}

// ParseOpenVPNConfig reads a provider's .ovpn file.
//
// Only what the hub must act on is interpreted: where to connect, over what, and
// whether the provider expects to take over routing. Everything else is preserved
// verbatim and handed to OpenVPN, which understands its own options far better than
// a reimplementation would -- and providers use plenty this hub has no business
// second-guessing.
func ParseOpenVPNConfig(content string) (domain.OpenVPNTunnel, error) {
	tunnel := domain.OpenVPNTunnel{Config: content}
	hasInlineCredentials, err := hasCompleteInlineCredentials(content)
	if err != nil {
		return domain.OpenVPNTunnel{}, err
	}

	var block string
	for number, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)

		// Inline blocks may contain anything; do not interpret their contents.
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
			name := strings.Trim(line, "<>/")
			if strings.HasPrefix(line, "</") {
				block = ""
			} else if inlineBlocks[name] {
				block = name
			}
			continue
		}
		if block != "" || line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) > 1 {
			if externalFileDirectives[fields[0]] {
				return domain.OpenVPNTunnel{}, fmt.Errorf("line %d: external file reference in %s is not allowed; inline the material in the SOPS-encrypted .ovpn file", number+1, fields[0])
			}
			if fields[0] == "tls-crypt-v2-verify" {
				return domain.OpenVPNTunnel{}, fmt.Errorf("line %d: external command reference in %s is not allowed; inline the material in the SOPS-encrypted .ovpn file", number+1, fields[0])
			}
		}
		switch fields[0] {
		case "remote":
			if len(fields) < 2 {
				return domain.OpenVPNTunnel{}, fmt.Errorf("line %d: remote needs a host", number+1)
			}
			remote := domain.OpenVPNRemote{Host: fields[1], Port: 1194, Protocol: "udp"}
			if len(fields) >= 3 {
				port, err := strconv.ParseUint(fields[2], 10, 16)
				if err != nil {
					return domain.OpenVPNTunnel{}, fmt.Errorf("line %d: invalid port %q", number+1, fields[2])
				}
				remote.Port = uint16(port)
			}
			if len(fields) >= 4 {
				remote.Protocol = fields[3]
			}
			tunnel.Remotes = append(tunnel.Remotes, remote)
		case "proto":
			if len(fields) >= 2 {
				tunnel.Protocol = fields[1]
			}
		case "dev":
			if len(fields) >= 2 {
				tunnel.Device = fields[1]
			}
		case "redirect-gateway":
			tunnel.RedirectsGateway = true
		case "auth-user-pass":
			if len(fields) == 1 && !hasInlineCredentials {
				return domain.OpenVPNTunnel{}, fmt.Errorf("line %d: auth-user-pass without a complete inline <auth-user-pass> block would prompt in unattended mode", number+1)
			}
		}
	}

	if len(tunnel.Remotes) == 0 {
		return domain.OpenVPNTunnel{}, fmt.Errorf("the configuration names no remote")
	}
	return tunnel, nil
}

func hasCompleteInlineCredentials(content string) (bool, error) {
	credentialLines := 0
	hasCompleteBlock := false
	inBlock := false
	blockLine := 0

	for number, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		switch line {
		case "<auth-user-pass>":
			if inBlock {
				return false, inlineCredentialBlockError(blockLine)
			}
			credentialLines = 0
			inBlock = true
			blockLine = number + 1
		case "</auth-user-pass>":
			if inBlock {
				if credentialLines != 2 {
					return false, inlineCredentialBlockError(blockLine)
				}
				hasCompleteBlock = true
				inBlock = false
			}
		case "":
			continue
		default:
			if inBlock {
				credentialLines++
			}
		}
	}

	if inBlock {
		return false, inlineCredentialBlockError(blockLine)
	}
	return hasCompleteBlock, nil
}

func inlineCredentialBlockError(line int) error {
	return fmt.Errorf("line %d: inline <auth-user-pass> must contain exactly two non-empty lines; OpenVPN would prompt in unattended mode", line)
}
