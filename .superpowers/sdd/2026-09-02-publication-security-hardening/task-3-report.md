# Task 3 Report: OpenVPN External Reference Hardening

Status: DONE

Commit: `acbcf7b8fb7aba746b00bd930fb672c46c433e11` (`security: reject OpenVPN external file references`)

## RED

`go test ./internal/adapters/linux -run 'TestParseOpenVPNConfig.*(External|Inline)'` failed before implementation. External credential and verifier references were accepted, and a complete inline credential block still triggered the unattended prompt error.

Additional RED checks showed that a missing password-only inline block and a malformed second credential block were accepted before validation was tightened.

## GREEN

- `go test ./internal/adapters/linux -run 'TestParseOpenVPNConfig.*(External|Inline)'`
- `go test ./internal/adapters/linux -run 'OpenVPN|OVPN'`
- `go test ./internal/adapters/linux`
- `git diff --check`

All passed.

## Self-review

- Rejects argument-bearing `auth-user-pass`, `http-proxy-user-pass`, `askpass`, `pkcs12`, and `crl-verify` with line and directive evidence.
- Rejects argument-bearing `tls-crypt-v2-verify` as an external command reference.
- Allows only complete `<auth-user-pass>` blocks with exactly two non-empty lines; any malformed block fails closed.
- Keeps provider config text unchanged after validation, so inline credentials reach the renderer.
- Retains the renderer's existing `script-security 0` defense.

## Concerns

None.

## Fix Round 1

Status: DONE

Commit: `4abe1e89cd074fa21e4cbb588807228380c2ecbb` (`fix: harden OpenVPN directive parsing`)

### RED

`go test ./internal/adapters/linux -run 'TestParseOpenVPNConfig.*(External|Inline)'` failed for all `--`-prefixed external-reference directives and for malformed self-closing and trailing inline tags, mismatched closes, nested blocks, and unterminated blocks.

### GREEN

- `go test ./internal/adapters/linux -run 'TestParseOpenVPNConfig.*(External|Inline)'`
- `go test ./internal/adapters/linux -run 'OpenVPN|OVPN'`
- `go test ./internal/adapters/linux`
- `git diff --check`

All passed.

### Self-review

- Removes one leading `--` before directive policy and parsing, while retaining the original directive spelling in error evidence.
- Validates all supported inline blocks with exact tag syntax, matching closes, no nesting, and an EOF closure check.
- Uses the same validated inline-line map for directive parsing, preventing block-state disagreement from hiding external references.
- Keeps exact two-line inline credential validation, unchanged provider content, and renderer-side `script-security 0`.

### Concerns

None.

## Fix Round 2

Status: DONE

Commit: `802b4d42c4985f5269664ccdea79660d9e5939e8` (`fix: preserve OpenVPN inline block content`)

### RED

`go test ./internal/adapters/linux -run 'TestParseOpenVPNConfig.*(External|Inline)'` failed because an auth password of `<value>` was parsed as an inline tag and because `<pkcs12>`, `<http-proxy-user-pass>`, and `<tls-crypt-v2>` were rejected as unsupported.

### GREEN

- `go test ./internal/adapters/linux -run 'TestParseOpenVPNConfig.*(External|Inline)'`
- `go test ./internal/adapters/linux -run 'OpenVPN|OVPN'`
- `go test ./internal/adapters/linux`
- `git diff --check`

All passed.

### Self-review

- Treats all `auth-user-pass` content as opaque except for the exact matching closing tag; `<value>` remains a valid password.
- A malformed trailing close remains inside the opaque block and fails closed at EOF, so it cannot expose a following path-bearing directive.
- Restores the original certificate/key blocks and supports inline `pkcs12`, proxy credentials, and `tls-crypt-v2` without changing provider content.
- Retains strict parsing outside `auth-user-pass`, external-reference rejection, and renderer-side `script-security 0`.

### Concerns

None.

## Fix Round 3

Status: DONE

Commit: `4e0cc7093c57c038807da230abc3530b44d24136` (`fix: parse OpenVPN connection blocks`)

### RED

`go test ./internal/adapters/linux -run 'TestParseOpenVPNConfig.*(External|Inline|Connection)'` failed because opaque material blocks still parsed `<value>` as a tag and `<connection>` was unsupported.

### GREEN

- `go test ./internal/adapters/linux -run 'TestParseOpenVPNConfig.*(External|Inline|Connection)'`
- `go test ./internal/adapters/linux -run 'OpenVPN|OVPN'`
- `go test ./internal/adapters/linux`
- `git diff --check`

All passed.

### Self-review

- All allowed material blocks now keep content opaque through their exact matching closing tag; only `auth-user-pass` counts its two non-empty credential lines.
- Exact structural opening and closing tags inside material still fail closed for nested or mismatched blocks; malformed trailing closes remain opaque and produce an unterminated-block failure.
- `<connection>` is transparent: its tags are validated and skipped, while its directives are parsed and subjected to the same external-reference policy.
- Provider text remains unchanged and renderer-side `script-security 0` remains in place.

### Concerns

None.

## Fix Round 4

Status: DONE

Commit: `f890a0719ed9a71de1b8680eca7231db376444c6` (`fix: preserve opaque OpenVPN block content`)

### RED

`go test ./internal/adapters/linux -run 'TestParseOpenVPNConfig.*(External|Inline|Connection)'` failed because `<ca>` inside both `<auth-user-pass>` and `<http-proxy-user-pass>` was interpreted as a nested structural block instead of opaque content.

### GREEN

- `go test ./internal/adapters/linux -run 'TestParseOpenVPNConfig.*(External|Inline|Connection)'`
- `go test ./internal/adapters/linux -run 'OpenVPN|OVPN'`
- `go test ./internal/adapters/linux`
- `git diff --check`

All passed.

### Self-review

- Opaque material blocks now close only on their exact matching closing tag; all other lines, including known opening tags and mismatched closing-tag-like strings, remain unchanged content.
- `<auth-user-pass>` still requires exactly two non-empty content lines, including when a tag-like string is the password.
- `<connection>` remains transparent and strict: malformed, nested, and unterminated blocks fail closed, and both ordinary and `--`-prefixed external credential references are rejected inside it.
- Provider text remains unchanged and renderer-side `script-security 0` remains in place.

### Concerns

None.

## Fix Round 5

Status: DONE

### RED

`make publication-check` failed because negative OpenVPN fixture names `revoked.pem` and `passphrase.txt` matched the public-hostname guard.

### GREEN

- `go test ./internal/adapters/linux -run 'OpenVPN|OVPN'`
- `go test ./internal/adapters/linux`
- `make publication-check`
- `git diff --check`

All passed.

### Self-review

- Replaced only the synthetic CRL and askpass fixture names with slash/underscore path-like names that cannot be interpreted as DNS literals.
- Retained both ordinary and `--`-prefixed directive coverage and their external-reference assertions.

### Concerns

None.
