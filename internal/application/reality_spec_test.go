package application

import (
	"testing"

	"vpn-hub/internal/domain"
)

func realityState(t *testing.T) domain.DesiredState {
	t.Helper()
	privateKey, _, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := validConfig(privateKey)
	cfg.Hub.Fallback.Reality = domain.RealityFallback{Enabled: true, ServerName: "www.example.com"}
	cfg.Devices = append(cfg.Devices, domain.Device{
		ID: "phone", Address: "10.80.0.3/32",
		PublicKey: cfg.Devices[0].PublicKey, Egress: domain.EgressDirect,
	})
	// Two devices, two public keys: the shared one above is only a placeholder.
	_, second, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Devices[1].PublicKey = second

	state, err := Service{}.BuildDesiredState(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// The listener's per-device marks and the packet filter's egress marks must be the
// same numbers: a device whose outbound carries one mark while the filter steers
// that mark elsewhere leaves through a tunnel it never chose.
func TestRealitySpecTakesItsMarksFromTheFirewallPlan(t *testing.T) {
	t.Parallel()
	state := realityState(t)
	plan, err := BuildFirewallPlan(state, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	privateKey, _, err := domain.GenerateRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	spec, err := BuildRealityIngressSpec(state, plan, privateKey)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !spec.Enabled || spec.Port != domain.RealityPort {
		t.Fatalf("spec = %+v, want an enabled listener on %d", spec, domain.RealityPort)
	}
	if spec.ServerName != "www.example.com" || spec.DNSAddress != state.Hub.DNSAddress {
		t.Errorf("spec carries the wrong server name or resolver: %+v", spec)
	}

	byDevice := make(map[string]domain.RealityUser, len(spec.Users))
	for _, user := range spec.Users {
		byDevice[user.DeviceID] = user
	}
	if len(byDevice) != len(state.Devices) {
		t.Fatalf("got %d users for %d devices", len(byDevice), len(state.Devices))
	}

	var want uint32
	for _, group := range plan.Egresses {
		if group.ID == "xray" {
			want = group.Mark
		}
	}
	if want == 0 {
		t.Fatal("the plan has no mark for the xray egress")
	}
	if got := byDevice["macbook"].Mark; got != want {
		t.Errorf("macbook's mark = %#x, want the plan's %#x", got, want)
	}
	// A device on direct is marked too, and not because the mark changes its route
	// -- it leaves by the uplink either way. The mark is what tells the packet
	// filter this connection has already chosen its way out, so output_mark leaves
	// it alone instead of re-marking it by destination into a private network's
	// tunnel that allowed_devices may not admit it to.
	var direct uint32
	for _, group := range plan.Egresses {
		if group.ID == domain.EgressDirect {
			direct = group.Mark
		}
	}
	if direct == 0 {
		t.Fatal("the plan has no mark for the direct egress")
	}
	if got := byDevice["phone"].Mark; got != direct {
		t.Errorf("a device on direct got mark %#x, want the plan's %#x", got, direct)
	}
	if byDevice["macbook"].UUID == "" || byDevice["macbook"].UUID == byDevice["phone"].UUID {
		t.Error("credentials are missing or shared between devices")
	}
}

func TestRealitySpecIsEmptyWhenTheFallbackIsOff(t *testing.T) {
	t.Parallel()
	state := realityState(t)
	state.Hub.Fallback.Reality.Enabled = false
	plan, err := BuildFirewallPlan(state, "eth0")
	if err != nil {
		t.Fatal(err)
	}

	spec, err := BuildRealityIngressSpec(state, plan, "")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if spec.Enabled || len(spec.Users) > 0 {
		t.Fatalf("spec = %+v, want nothing to run", spec)
	}
}

// A revoked device is removed from the revision before it is compiled, so it must
// disappear from the listener's user list on the same pass -- otherwise the
// credential keeps working on a path the revocation never touched.
func TestRealitySpecDropsRevokedDevices(t *testing.T) {
	t.Parallel()
	privateKey, _, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := validConfig(privateKey)
	cfg.Hub.Fallback.Reality = domain.RealityFallback{Enabled: true, ServerName: "www.example.com"}

	state, err := Service{}.BuildDesiredState(RemoveRevoked(cfg, []string{"macbook"}))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildFirewallPlan(state, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	realityKey, _, err := domain.GenerateRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	spec, err := BuildRealityIngressSpec(state, plan, realityKey)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, user := range spec.Users {
		if user.DeviceID == "macbook" {
			t.Fatal("a revoked device is still admitted through the fallback")
		}
	}
}
