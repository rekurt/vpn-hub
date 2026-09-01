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
	"auth-user-pass": true, "http-proxy-user-pass": true, "pkcs12": true, "tls-crypt-v2": true,
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
	inlineLines, hasInlineCredentials, err := validateOpenVPNInlineBlocks(content)
	if err != nil {
		return domain.OpenVPNTunnel{}, err
	}

	for number, raw := range strings.Split(content, "\n") {
		if inlineLines[number] {
			continue
		}
		line := strings.TrimSpace(raw)

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		fields := strings.Fields(line)
		directive := strings.TrimPrefix(fields[0], "--")
		if len(fields) > 1 {
			if externalFileDirectives[directive] {
				return domain.OpenVPNTunnel{}, fmt.Errorf("line %d: external file reference in %s is not allowed; inline the material in the SOPS-encrypted .ovpn file", number+1, fields[0])
			}
			if directive == "tls-crypt-v2-verify" {
				return domain.OpenVPNTunnel{}, fmt.Errorf("line %d: external command reference in %s is not allowed; inline the material in the SOPS-encrypted .ovpn file", number+1, fields[0])
			}
		}
		switch directive {
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

func validateOpenVPNInlineBlocks(content string) (map[int]bool, bool, error) {
	credentialLines := 0
	hasCompleteBlock := false
	inlineLines := make(map[int]bool)
	block := ""
	blockLine := 0

	for number, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if inlineBlocks[block] {
			inlineLines[number] = true
			if line == "</"+block+">" {
				if block == "auth-user-pass" {
					if credentialLines != 2 {
						return nil, false, inlineCredentialBlockError(blockLine)
					}
					hasCompleteBlock = true
				}
				block = ""
				continue
			}
			if strings.HasPrefix(line, "<") {
				name, closing, err := parseOpenVPNInlineTag(line)
				if err == nil && closing {
					return nil, false, fmt.Errorf("line %d: mismatched inline block close </%s> for <%s>", number+1, name, block)
				}
				if err == nil && isOpenVPNInlineBlock(name) {
					return nil, false, fmt.Errorf("line %d: nested inline block <%s> inside <%s> is not allowed", number+1, name, block)
				}
			}
			if block == "auth-user-pass" && line != "" {
				credentialLines++
			}
			continue
		}
		if strings.HasPrefix(line, "<") {
			name, closing, err := parseOpenVPNInlineTag(line)
			if err != nil {
				return nil, false, fmt.Errorf("line %d: malformed inline block tag %q", number+1, line)
			}
			inlineLines[number] = true
			if closing {
				if block == "" {
					return nil, false, fmt.Errorf("line %d: unexpected inline block close </%s>", number+1, name)
				}
				if block != name {
					return nil, false, fmt.Errorf("line %d: mismatched inline block close </%s> for <%s>", number+1, name, block)
				}
				if block == "auth-user-pass" {
					if credentialLines != 2 {
						return nil, false, inlineCredentialBlockError(blockLine)
					}
					hasCompleteBlock = true
				}
				block = ""
				continue
			}
			if !isOpenVPNInlineBlock(name) {
				return nil, false, fmt.Errorf("line %d: unsupported inline block <%s>", number+1, name)
			}
			if block != "" {
				return nil, false, fmt.Errorf("line %d: nested inline block <%s> inside <%s> is not allowed", number+1, name, block)
			}
			block = name
			credentialLines = 0
			blockLine = number + 1
			continue
		}
	}

	if block != "" {
		return nil, false, fmt.Errorf("line %d: unterminated inline block <%s>", blockLine, block)
	}
	return inlineLines, hasCompleteBlock, nil
}

func isOpenVPNInlineBlock(name string) bool {
	return inlineBlocks[name] || name == "connection"
}

func parseOpenVPNInlineTag(line string) (string, bool, error) {
	if len(line) < 3 || !strings.HasSuffix(line, ">") {
		return "", false, fmt.Errorf("not a tag")
	}

	name := line[1 : len(line)-1]
	closing := strings.HasPrefix(name, "/")
	if closing {
		name = name[1:]
	}
	if name == "" || strings.ContainsAny(name, " \t\r\n<>/") {
		return "", false, fmt.Errorf("not a tag")
	}
	return name, closing, nil
}

func inlineCredentialBlockError(line int) error {
	return fmt.Errorf("line %d: inline block <auth-user-pass> must contain exactly two non-empty lines; OpenVPN would prompt in unattended mode", line)
}
