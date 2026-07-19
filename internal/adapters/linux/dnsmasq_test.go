package linux

import (
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

func dnsPlan() domain.DNSPlan {
	return domain.DNSPlan{
		ListenAddress: "10.80.0.1",
		ClientCIDR:    "10.80.0.0/24",
		Zones: []domain.DNSZoneRoute{{
			Zone: "corp.internal", Resolvers: []string{"10.20.0.53"}, Set: "internal_corp_a",
		}},
		UpstreamNamespace: "vpn-hub-provider-nl",
		UpstreamAddress:   "10.90.0.2",
		PublicResolvers:   []string{"1.1.1.1"},
	}
}

// The nftset directive is what makes a private name usable: without it the address
// resolves and then routes out of the internet path.
func TestPrivateZonesAreSentToTheirResolverAndSet(t *testing.T) {
	t.Parallel()
	rendered := RenderHubResolver(dnsPlan())
	for _, wanted := range []string{
		"server=/corp.internal/10.20.0.53",
		"nftset=/corp.internal/inet#vpn_hub#internal_corp_a",
	} {
		if !strings.Contains(rendered, wanted) {
			t.Errorf("missing %q:\n%s", wanted, rendered)
		}
	}
}

// Public queries go to the resolver inside the egress namespace, never straight out
// of the hub, or the provider carries the traffic while DNS still names the hub.
func TestPublicQueriesGoToTheNamespaceResolver(t *testing.T) {
	t.Parallel()
	rendered := RenderHubResolver(dnsPlan())
	if !strings.Contains(rendered, "server=10.90.0.2") {
		t.Errorf("expected forwarding to the namespace resolver:\n%s", rendered)
	}
	if strings.Contains(rendered, "server=1.1.1.1") {
		t.Errorf("the hub resolver must not query public servers directly:\n%s", rendered)
	}
}

func TestWithoutANamespaceTheHubQueriesPublicServers(t *testing.T) {
	t.Parallel()
	plan := dnsPlan()
	plan.UpstreamNamespace = ""
	plan.UpstreamAddress = ""

	rendered := RenderHubResolver(plan)
	if !strings.Contains(rendered, "server=1.1.1.1") {
		t.Errorf("expected direct public resolvers:\n%s", rendered)
	}
}

func TestUpstreamResolverOnlyForwards(t *testing.T) {
	t.Parallel()
	rendered := RenderUpstreamResolver(dnsPlan())
	if !strings.Contains(rendered, "listen-address=10.90.0.2") {
		t.Errorf("expected it to listen inside the namespace:\n%s", rendered)
	}
	if strings.Contains(rendered, "nftset=") {
		t.Error("only the hub resolver populates sets")
	}
}

// The resolver answers clients, not the internet.
func TestResolverIsNotOpenToTheWorld(t *testing.T) {
	t.Parallel()
	rendered := RenderHubResolver(dnsPlan())
	for _, wanted := range []string{"bind-interfaces", "local-service", "listen-address=10.80.0.1"} {
		if !strings.Contains(rendered, wanted) {
			t.Errorf("missing %q:\n%s", wanted, rendered)
		}
	}
}
