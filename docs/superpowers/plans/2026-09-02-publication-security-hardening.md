# Publication Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove every validated source-level publication blocker while preserving VPN Hub's supported routing, provider, and operations workflows.

**Architecture:** Harden untrusted provider inputs before they reach privileged networking processes, make public DNS follow each device's selected egress, and add repository-level leak guards. Keep policy decisions in domain/application plans and Linux adapters limited to deterministic rendering and host operations.

**Tech Stack:** Go 1.26, Cobra, nftables, dnsmasq, OpenVPN 2.6+, Linux network namespaces, OpenTofu, shell verification

**Spec:** `docs/superpowers/specs/2026-09-01-publication-site-docs-design.md`

## Global Constraints

- English is the canonical language for source-facing errors and public documentation.
- Preserve fail-closed routing: an unhealthy selected egress must never become direct traffic.
- Preserve mixed per-device egress; do not solve DNS privacy by prohibiting the product's primary use case.
- Provider-controlled content is untrusted even after a successful HTTPS fetch.
- No real keys, tokens, hosts, chat IDs, provider URLs, or private infrastructure identifiers may enter fixtures or examples.
- Use TDD for every behavior change and make a conventional commit after each task.
- Do not rewrite Git history or rotate external credentials without the explicit checkpoint in Task 8.

---

### Task 1: Replace the Leaked AWG Fixture and Add Publication Guards

**Files:**
- Modify: `internal/adapters/linux/awgdump_test.go:9`
- Modify: `.gitignore`
- Create: `scripts/check-publication.sh`
- Create: `scripts/check-publication_test.sh`
- Create: `scripts/publication-allowlist.txt`
- Modify: `Makefile`

**Interfaces:**
- Produces: `scripts/check-publication.sh [--history]`, exit code 0 for a clean tree and non-zero with matching file/ref names for publication-sensitive data.
- Produces: `make publication-check`, the local equivalent of the CI publication guard.

- [ ] **Step 1: Write the failing shell tests**

Create a temporary Git repository in `scripts/check-publication_test.sh`, copy the checker into it, and assert these cases:

```sh
expect_pass clean printf '%s\n' 'endpoint: vpn.example.com:51820'
expect_fail awg-private printf '%s\n' 'private_key = YK8abDsljvw7F3rfkYsup5IR39Q6gCcz/d5t0828jX0='
expect_fail telegram-token printf '%s\n' 'token: 123456789:AAExampleSecretValueThatMustFail'
expect_fail runtime-state printf '%s\n' '{"revision":"abc","hub":{"endpoint":"203.0.113.7:51820"}}'
expect_pass synthetic-public printf '%s\n' 'public_key: W/kKaUP1n48AgIzxs8po0HKV+UEk1vMcTuBW648atSE='
expect_fail unknown-host printf '%s\n' 'endpoint: vpn.personal-domain.net:51820'
expect_fail unknown-public-ip printf '%s\n' 'endpoint: 93.184.216.34:51820'
expect_pass documentation-host printf '%s\n' 'endpoint: vpn.example.com:51820'
```

The test helper must commit each fixture so `--history` can also prove a removed secret remains detectable.

- [ ] **Step 2: Run the test to verify the checker is absent**

Run: `sh scripts/check-publication_test.sh`

Expected: FAIL because `scripts/check-publication.sh` does not exist.

- [ ] **Step 3: Replace the lab dump with a synthetic dump**

Rename `realDump` to `syntheticDump`, remove the lab-capture claim, and generate all private/public-looking values from documented test-only constants. Keep the field count, never-handshaken peer, obfuscation parameters, and parser assertions unchanged.

- [ ] **Step 4: Implement the publication checker**

The checker must:

```sh
git grep -nE '(client_private_key|private_key)[[:space:]]*[:=][[:space:]]*[A-Za-z0-9+/]{42,}={0,2}' -- ':!scripts/check-publication_test.sh'
git grep -nE '[0-9]{8,10}:AA[A-Za-z0-9_-]{30,}' -- ':!scripts/check-publication_test.sh'
git ls-files | grep -E '(^|/)(state|device-profiles|backups?)/|desired-state\.json$'
```

Invert each check so a match prints evidence and exits non-zero. `--history` must enumerate `git rev-list --all`, scan blobs with `git grep <commit>`, and also report author email domains outside `users.noreply.github.com` plus commit trailers containing assistant attribution.

Extract IPv4 literals and DNS names from tracked text. Allow RFC 1918, RFC 5737, loopback, link-local, `*.example.com`, `*.example.net`, `*.example.org`, and the reviewed external endpoints listed in `scripts/publication-allowlist.txt`: `api.telegram.org`, `github.com`, `objects.githubusercontent.com`, `ppa.launchpadcontent.net`, `1.1.1.1`, and `9.9.9.9`. Any other public literal fails with file and line, so an operator must either replace it or review and add a justified allowlist entry.

Add `/state/`, `/device-profiles/`, `/backups/`, `desired-state.json`, and `*.tfstate*` to `.gitignore`.

- [ ] **Step 5: Wire and verify the guard**

Add this Make target:

```make
## publication-check: reject secrets and runtime state before publishing
publication-check:
	sh scripts/check-publication.sh
	sh scripts/check-publication_test.sh
```

Run: `make publication-check && go test ./internal/adapters/linux -run TestParseDump`

Expected: PASS and no lab-derived private key in `git grep` output.

- [ ] **Step 6: Commit**

```bash
git add .gitignore Makefile scripts/check-publication.sh scripts/check-publication_test.sh scripts/publication-allowlist.txt internal/adapters/linux/awgdump_test.go
git commit -m "security: remove leaked fixture and guard publication"
```

### Task 2: Use a Private Temporary File in the Root nftables Test

**Files:**
- Modify: `internal/adapters/linux/localguard_integration_test.go:75`
- Create: `internal/adapters/linux/localguard_source_test.go`

**Interfaces:**
- Consumes: Go `testing.T.TempDir()`.
- Produces: no predictable path in a shared temporary directory.

- [ ] **Step 1: Add a source-level regression assertion**

Add a non-integration test in `internal/adapters/linux/localguard_source_test.go` named `TestPrivilegedIntegrationTestsDoNotUseFixedTmpFiles`. Read `localguard_integration_test.go` and fail if it contains `"/tmp/localguard.nft"`.

- [ ] **Step 2: Run it and verify the failure**

Run: `go test ./internal/adapters/linux -run TestPrivilegedIntegrationTestsDoNotUseFixedTmpFiles`

Expected: FAIL naming `/tmp/localguard.nft`.

- [ ] **Step 3: Replace the fixed path**

Use:

```go
rulesPath := filepath.Join(t.TempDir(), "localguard.nft")
if err := os.WriteFile(rulesPath, []byte(linux.RenderRuleset(plan)), 0o600); err != nil {
	t.Fatal(err)
}
if out, err := exec.Command("nft", "-f", rulesPath).CombinedOutput(); err != nil {
	t.Fatalf("the ruleset did not load: %v\n%s", err, out)
}
```

Import `path/filepath`. The directory is private to the root test process and is removed by the testing package.

- [ ] **Step 4: Verify**

Run: `go test ./internal/adapters/linux -run TestPrivilegedIntegrationTestsDoNotUseFixedTmpFiles && go vet -tags=integration ./internal/adapters/linux`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/adapters/linux/localguard_integration_test.go internal/adapters/linux/localguard_source_test.go
git commit -m "test: isolate privileged nftables fixture"
```

### Task 3: Remove OpenVPN Host File References Without Dropping Credential Support

**Files:**
- Modify: `internal/adapters/linux/ovpn.go`
- Modify: `internal/adapters/linux/ovpn_test.go`
- Modify: `internal/adapters/linux/openvpn_parse_test.go`

**Interfaces:**
- Produces: `ParseOpenVPNConfig(content string) (domain.OpenVPNTunnel, error)` accepts `<auth-user-pass>...</auth-user-pass>` and rejects every path-bearing `auth-user-pass`, `http-proxy-user-pass`, `askpass`, `pkcs12`, `crl-verify`, and `tls-crypt-v2-verify` directive.
- Preserves: provider config text after validation so supported inline certificates, keys, and credentials reach OpenVPN unchanged.

- [ ] **Step 1: Add failing table tests**

Add cases asserting:

```go
{"relative auth file", "auth-user-pass credentials.txt", "external file reference"},
{"absolute auth file", "auth-user-pass /etc/shadow", "external file reference"},
{"proxy auth file", "http-proxy-user-pass proxy.auth", "external file reference"},
{"pkcs12 file", "pkcs12 identity.p12", "external file reference"},
{"script verifier", "tls-crypt-v2-verify /usr/local/bin/check", "external command reference"},
```

Add a positive case with a complete inline block:

```text
<auth-user-pass>
demo-user
demo-password
</auth-user-pass>
```

and a negative case where the password line is absent.

- [ ] **Step 2: Run the tests and verify failure**

Run: `go test ./internal/adapters/linux -run 'TestParseOpenVPNConfig.*(External|Inline)'`

Expected: FAIL because path-bearing directives are currently preserved.

- [ ] **Step 3: Implement an explicit directive policy**

Add `auth-user-pass` to `inlineBlocks`. Track whether a complete inline credential block contains exactly two non-empty lines. Before accepting any ordinary directive, reject the file/command-reference directive set above when it has arguments. Keep `script-security 0` in the renderer as a second control.

Return errors in this shape:

```go
return domain.OpenVPNTunnel{}, fmt.Errorf("line %d: external file reference in %s is not allowed; inline the material in the SOPS-encrypted .ovpn file", number+1, fields[0])
```

For `auth-user-pass` without an argument, accept only when the complete inline block exists; otherwise return an unattended-prompt error.

- [ ] **Step 4: Verify parser and renderer behavior**

Run: `go test ./internal/adapters/linux -run 'OpenVPN|OVPN'`

Expected: PASS; rendered output contains inline credentials and no accepted external path.

- [ ] **Step 5: Commit**

```bash
git add internal/adapters/linux/ovpn.go internal/adapters/linux/ovpn_test.go internal/adapters/linux/openvpn_parse_test.go
git commit -m "security: reject OpenVPN external file references"
```

### Task 4: Bound Subscription Parsing and Aggregate Refresh Time

**Files:**
- Modify: `internal/adapters/linux/subscription.go`
- Modify: `internal/adapters/linux/subscription_test.go`
- Modify: `internal/application/subscription.go`
- Modify: `internal/application/subscription_test.go`

**Interfaces:**
- Produces: exported limits `MaxSubscriptionCandidates = 32`, `MaxSubscriptionLineBytes = 8192`, and `DefaultSubscriptionRefreshTimeout = 2 * time.Minute`.
- Preserves: `ParseSubscription([]byte) ([]domain.ProxyTunnel, error)` and `SubscriptionRefresher.Refresh(...)` signatures.

- [ ] **Step 1: Add parser limit tests**

Generate 33 syntactically valid unique VLESS links and assert the parser returns an error containing `more than 32 usable candidates`. Generate one 8193-byte line and assert an error containing `line exceeds 8192 bytes`.

- [ ] **Step 2: Add an aggregate deadline test**

Give `SubscriptionRefresher` a `Timeout time.Duration` field. In the test, set `Timeout: 20 * time.Millisecond`; make `Prove` block until `ctx.Done()` and assert `Refresh` returns `subscription refresh exceeded 20ms` within 200 ms without calling the store.

- [ ] **Step 3: Run focused tests to verify failure**

Run: `go test ./internal/adapters/linux ./internal/application -run 'Subscription.*(Limit|Deadline|Timeout)'`

Expected: FAIL because limits and `Timeout` do not exist.

- [ ] **Step 4: Implement bounded parsing and refresh**

Use `bufio.Scanner`, call `scanner.Buffer(make([]byte, 4096), MaxSubscriptionLineBytes)`, stop after 32 usable candidates, and distinguish scanner length errors from a payload with no supported link.

In `Refresh`, derive:

```go
timeout := r.Timeout
if timeout <= 0 {
	timeout = DefaultSubscriptionRefreshTimeout
}
refreshCtx, cancel := context.WithTimeout(ctx, timeout)
defer cancel()
```

Pass `refreshCtx` to fetch, prove, and store. Convert only `context.DeadlineExceeded` caused by this derived context into the explicit aggregate-timeout error.

- [ ] **Step 5: Verify**

Run: `go test -race ./internal/adapters/linux ./internal/application ./internal/delivery/bot`

Expected: PASS and the bot mutation gate is released after the bounded refresh returns.

- [ ] **Step 6: Commit**

```bash
git add internal/adapters/linux/subscription.go internal/adapters/linux/subscription_test.go internal/application/subscription.go internal/application/subscription_test.go
git commit -m "security: bound subscription refresh work"
```

### Task 5: Resolve and Pin Public VLESS Destinations

**Files:**
- Create: `internal/adapters/health/public_endpoint.go`
- Create: `internal/adapters/health/public_endpoint_test.go`
- Modify: `internal/domain/proxy.go`
- Modify: `internal/adapters/linux/tunnelconfig.go`
- Modify: `internal/adapters/linux/tunnelconfig_test.go`
- Modify: `internal/delivery/cli/hubctl.go`
- Modify: `internal/delivery/bot/bot.go`
- Modify: `internal/delivery/bot/handlers_subs.go`
- Modify: `internal/wiring/wiring.go`

**Interfaces:**
- Produces: `type EndpointResolver interface { LookupNetIP(context.Context, string, string) ([]netip.Addr, error) }`.
- Produces: `health.PinPublicEndpoint(ctx context.Context, resolver EndpointResolver, candidate domain.ProxyTunnel) (domain.ProxyTunnel, error)`.
- Produces: `domain.ProxyTunnel.OriginServer string` serialized only in memory and used to preserve TLS SNI and HTTP Host when `Server` is replaced by a validated IP.

- [ ] **Step 1: Write public-address policy tests**

Use a fake resolver and cover loopback, RFC1918, link-local, multicast, unspecified, documentation ranges, a mixed public/private answer, IPv4 public, IPv6 public, and deterministic sorting. A candidate is accepted only when every resolved address is globally routable and not a special-purpose range; a mixed answer is rejected.

Assert a hostname candidate becomes:

```go
domain.ProxyTunnel{
	Server: "8.8.8.8",
	OriginServer: "edge.provider.example",
	TLS: domain.ProxyTLS{ServerName: "edge.provider.example"},
}
```

The fake resolver returns `8.8.8.8` without network access. Production classification must follow `netip` plus an explicit IANA special-purpose prefix table and must reject documentation ranges as non-routable test space.

- [ ] **Step 2: Run and verify failure**

Run: `go test ./internal/adapters/health -run PinPublicEndpoint`

Expected: FAIL because the resolver does not exist.

- [ ] **Step 3: Implement destination resolution and pinning**

For an IP literal, validate it directly. For a hostname, resolve `ip`, normalize IPv4-mapped values, reject if any answer is special-use, sort with `Addr.Compare`, and pin the first address. Before replacing the hostname, preserve it as `OriginServer`; if TLS server name or WebSocket/HTTP Upgrade Host is empty, populate it from the original hostname.

- [ ] **Step 4: Enforce the policy on every load and promotion path**

Add `Resolver health.EndpointResolver` to `linux.TunnelConfigFiles` and pin static/subscription link files in `Load`. Wire `net.DefaultResolver` in `internal/wiring/wiring.go`. In CLI and bot refresh flows, map parsed candidates through `PinPublicEndpoint` before canary selection and persist the pinned candidate returned by the prover.

Do not apply the restriction to operator-declared private-network WireGuard/OpenVPN endpoints; this task is specifically for provider subscription/static VLESS destinations that otherwise create blind internal requests.

- [ ] **Step 5: Verify all paths**

Run: `go test -race ./internal/adapters/health ./internal/adapters/linux ./internal/delivery/cli ./internal/delivery/bot ./internal/wiring`

Expected: PASS; private VLESS destinations fail before sing-box starts, while public hostnames retain correct SNI/Host.

- [ ] **Step 6: Commit**

```bash
git add internal/adapters/health/public_endpoint.go internal/adapters/health/public_endpoint_test.go internal/domain/proxy.go internal/adapters/linux/tunnelconfig.go internal/adapters/linux/tunnelconfig_test.go internal/delivery/cli/hubctl.go internal/delivery/bot/bot.go internal/delivery/bot/handlers_subs.go internal/wiring/wiring.go
git commit -m "security: pin VLESS candidates to public endpoints"
```

### Task 6: Make Public DNS Follow Each Device's Egress

**Files:**
- Modify: `internal/domain/dns.go`
- Modify: `internal/domain/firewall.go`
- Modify: `internal/application/dns_plan.go`
- Modify: `internal/application/dns_plan_test.go`
- Modify: `internal/application/firewall_plan.go`
- Modify: `internal/application/firewall_plan_test.go`
- Modify: `internal/adapters/linux/dnsmasq.go`
- Modify: `internal/adapters/linux/dnsmasq_test.go`
- Modify: `internal/adapters/linux/nftables.go`
- Modify: `internal/adapters/linux/nftables_test.go`
- Modify: `internal/adapters/linux/testdata/direct-only.nft`
- Modify: `internal/adapters/linux/testdata/tunnel-and-internal.nft`
- Modify: `internal/adapters/linux/integration_test.go`

**Interfaces:**
- Replaces: singular `DNSPlan.UpstreamNamespace` and `UpstreamAddress`.
- Produces: `DNSPlan.EgressResolvers []DNSEgressResolver` with fields `EgressID`, `ClientAddresses`, `HubAddress`, `Namespace`, `NamespaceAddress`, and `PublicResolvers`.
- Produces: `FirewallPlan.DNSDestinations []DNSDestination` with `ClientAddresses` and `ResolverAddress`.

- [ ] **Step 1: Write the application-level privacy test**

Create three devices assigned to `direct`, `wg-nl`, and `xray-de`. Assert `BuildDNSPlan` emits three deterministic resolver entries, each with only its own device address. Assert tunneled entries use the corresponding spec's host and peer veth addresses and direct uses `Hub.DNSAddress` without a namespace.

- [ ] **Step 2: Write renderer tests**

Assert:

- each egress gets a distinct main-namespace dnsmasq config;
- each tunneled egress gets one namespace forwarder;
- private-zone `server=/zone/address` and `nftset` directives appear in every main resolver;
- nftables DNATs UDP and TCP port 53 from each device source to its resolver address;
- no global “busiest egress” forwarder remains.

- [ ] **Step 3: Run the focused tests and verify failure**

Run: `go test ./internal/application ./internal/adapters/linux -run 'DNS|Resolver'`

Expected: FAIL against the singular resolver model.

- [ ] **Step 4: Implement the domain and plan model**

Use each egress spec's main-side `HostAddress` as the main resolver bind address and peer-side `PeerAddress` as the namespace forwarder address. Direct DNS continues to bind `Hub.DNSAddress`. Carry the source device addresses already present in `FirewallPlan.Egresses` into `DNSDestinations`.

Reject a plan if a non-direct egress has assigned clients but no matching egress spec. Sort entries by `EgressID` and client addresses for byte-identical reconciliation.

- [ ] **Step 5: Implement dnsmasq lifecycle**

Name main resolvers `vpn-hub-resolver-client-<safe-egress>` and namespace forwarders `vpn-hub-resolver-public-<safe-egress>`. Write one main config per entry containing private-zone routes plus either direct public servers or its namespace forwarder. Start namespace forwarders before main resolvers and sweep stale units from both prefixes.

- [ ] **Step 6: Implement source-aware DNS DNAT**

In `prerouting_nat`, emit source-address sets per egress and rules of this form for UDP and TCP:

```nft
iifname "awg0" ip saddr @dns_clients_wg_nl udp dport 53 dnat ip to 10.90.0.1:53
```

Keep the final catch-all DNAT to `Hub.DNSAddress` only as a defensive path for an admitted client missing from the plan. Input rules must accept port 53 on all planned resolver addresses from the ingress interface and no other source.

- [ ] **Step 7: Add an integration scenario**

Create two fake egress namespaces with DNS listeners that return distinct TXT/A markers. Query the same public name from two client addresses and assert each receives the marker from its selected egress. Also query a private zone from both clients and assert both reach the private-network resolver.

- [ ] **Step 8: Verify**

Run: `go test -race ./internal/application ./internal/adapters/linux`

On Linux or the testbox, run: `make test-integration-box ARGS='-run DNS'`

Expected: all unit/golden tests and the mixed-egress DNS integration scenario pass.

- [ ] **Step 9: Commit**

```bash
git add internal/domain/dns.go internal/domain/firewall.go internal/application/dns_plan.go internal/application/dns_plan_test.go internal/application/firewall_plan.go internal/application/firewall_plan_test.go internal/adapters/linux/dnsmasq.go internal/adapters/linux/dnsmasq_test.go internal/adapters/linux/nftables.go internal/adapters/linux/nftables_test.go internal/adapters/linux/testdata internal/adapters/linux/integration_test.go
git commit -m "fix: route DNS through each device egress"
```

### Task 7: Harden Provisioning Defaults and SOPS Runtime Access

**Files:**
- Modify: `deploy/terraform/variables.tf`
- Modify: `deploy/terraform/terraform.tfvars.example`
- Modify: `deploy/terraform/cloud-init.yaml`
- Modify: `deploy/systemd/vpn-hub-agent.service`
- Modify: `deploy/systemd/vpn-hub-bot.service`
- Create: `deploy/terraform/tests/security.tftest.hcl`

**Interfaces:**
- Produces: an explicitly required `ssh_allowed_cidrs` with validation rejecting `0.0.0.0/0` and `::/0` unless `allow_global_ssh = true`.
- Produces: installed `sops` plus a fixed `SOPS_AGE_KEY_FILE=/etc/vpn-hub/age/keys.txt` available to both services under their filesystem sandbox.

- [ ] **Step 1: Add failing OpenTofu tests**

Add test runs that assert:

```hcl
variables {
  ssh_allowed_cidrs = ["0.0.0.0/0"]
  allow_global_ssh  = false
}
expect_failures = [var.ssh_allowed_cidrs]
```

and a passing run for `198.51.100.10/32`. Add a separate passing break-glass run with `allow_global_ssh = true`.

- [ ] **Step 2: Run and verify failure**

Run: `tofu -chdir=deploy/terraform test`

Expected: FAIL because the validation and override do not exist.

- [ ] **Step 3: Implement explicit SSH exposure**

Remove the permissive default, add `allow_global_ssh` defaulting to false, and validate all CIDRs. Set the example to the documentation-only `198.51.100.10/32` with a comment requiring replacement.

- [ ] **Step 4: Complete SOPS provisioning**

In cloud-init, install `sops-v3.13.3.linux.amd64` and verify SHA-256 `e5bec3346a873ae91d871550f3e698c1aad962aff462a080e40f25fde17fef6b`. Create `/etc/vpn-hub/age` mode `0700`, and document that the operator places `keys.txt` mode `0600` there. Set `/etc/vpn-hub` mode `0700` at creation time.

Add to both units:

```ini
Environment=SOPS_AGE_KEY_FILE=/etc/vpn-hub/age/keys.txt
ReadOnlyPaths=/etc/vpn-hub
```

Retain the writable runtime and state directories already required by each service.

- [ ] **Step 5: Verify provisioning files**

Run: `tofu -chdir=deploy/terraform fmt -check -diff && tofu -chdir=deploy/terraform init -backend=false && tofu -chdir=deploy/terraform validate && tofu -chdir=deploy/terraform test`

Run: `systemd-analyze verify deploy/systemd/vpn-hub-agent.service deploy/systemd/vpn-hub-bot.service`

Expected: PASS on a Linux systemd environment.

- [ ] **Step 6: Commit**

```bash
git add deploy/terraform/variables.tf deploy/terraform/terraform.tfvars.example deploy/terraform/cloud-init.yaml deploy/terraform/tests/security.tftest.hcl deploy/systemd/vpn-hub-agent.service deploy/systemd/vpn-hub-bot.service
git commit -m "security: harden provisioning defaults"
```

### Task 8: Verify Remediation and Obtain the External Rotation Checkpoint

**Files:**
- Create: `docs/publication/security-remediation.md`
- Modify: `docs/superpowers/plans/2026-09-01-publication-security-hardening.md`

**Interfaces:**
- Produces: evidence mapping all 12 validated findings to a fix commit and verification command.
- Requires: operator confirmation that the lab AmneziaWG key from the old fixture was rotated.

- [ ] **Step 1: Run the complete local verification suite**

Run:

```bash
make publication-check
make ci
make test-integration-box
git diff --check
```

Expected: every supported local check passes.

- [ ] **Step 2: Run a final security diff scan**

Review the diff from `6db1c4c3cdb88240363b38bbcd09a8db02d98075` to `HEAD`, validate every candidate, and record whether each original finding is fixed, intentionally deferred, or replaced by a stronger control. No medium finding may remain unresolved for the public release.

- [ ] **Step 3: Record the evidence**

Create a table with these exact rule IDs:

```text
external-file-reference.openvpn-auth-user-pass
resource-exhaustion.subscription-candidates
network-exposure.terraform-ssh-default
ssrf.vless-candidate-destination
supply-chain.mutable-github-actions
artifact-provenance.unvalidated-run-id
release-integrity.ci-not-required
sensitive-data-exposure.local-state-not-ignored
checksum-manifest.release-path-mismatch
privacy-leak.shared-dns-egress
secret-exposure.amneziawg-private-key-fixture
insecure-temp-file.root-nft-integration-test
```

Release-pipeline rules reference the commits produced by the release plan.

- [ ] **Step 4: Pause for key-rotation confirmation**

Ask the operator to confirm that the lab interface key beginning with the historical fixture's fingerprint has been rotated or the laboratory host destroyed. Do not copy the full private key into the prompt, logs, or remediation document.

- [ ] **Step 5: Commit verified evidence**

```bash
git add docs/publication/security-remediation.md docs/superpowers/plans/2026-09-01-publication-security-hardening.md
git commit -m "docs: record publication security verification"
```
