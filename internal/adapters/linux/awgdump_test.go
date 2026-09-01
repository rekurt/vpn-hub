package linux

import (
	"strings"
	"testing"
	"time"
)

const (
	// Test-only base64 values. They do not identify a real interface or peer.
	syntheticInterfacePrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	syntheticInterfacePublicKey  = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	syntheticPeerPublicKey       = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
)

// syntheticDump has one interface with obfuscation parameters and one peer that has
// never handshaken.
const syntheticDump = syntheticInterfacePrivateKey + "\t" + syntheticInterfacePublicKey + "\t51820\t4\t64\t256\t15\t30\t0\t0\t12345\t23456\t34567\t45678\t(null)\t(null)\t(null)\t(null)\t(null)\toff\n" +
	syntheticPeerPublicKey + "\t(none)\t(none)\t10.80.0.2/32\t0\t0\t0\toff\n"

func TestParseDump(t *testing.T) {
	t.Parallel()
	state, err := ParseDump(syntheticDump)
	if err != nil {
		t.Fatalf("ParseDump: %v", err)
	}

	if !state.Exists {
		t.Error("Exists = false")
	}
	if want := syntheticInterfacePublicKey; state.PublicKey != want {
		t.Errorf("PublicKey = %q, want %q", state.PublicKey, want)
	}
	if state.ListenPort != 51820 {
		t.Errorf("ListenPort = %d, want 51820", state.ListenPort)
	}
	if len(state.Peers) != 1 {
		t.Fatalf("expected one peer, got %d", len(state.Peers))
	}

	peer := state.Peers[0]
	if len(peer.AllowedIPs) != 1 || peer.AllowedIPs[0] != "10.80.0.2/32" {
		t.Errorf("AllowedIPs = %v", peer.AllowedIPs)
	}
	if !peer.LatestHandshake.IsZero() {
		t.Errorf("a peer that never handshook must report the zero time, got %v", peer.LatestHandshake)
	}
}

func TestParseDumpReadsHandshakeTime(t *testing.T) {
	t.Parallel()
	dump := strings.Replace(syntheticDump, "10.80.0.2/32\t0\t0\t0", "10.80.0.2/32\t1752900000\t1024\t2048", 1)
	state, err := ParseDump(dump)
	if err != nil {
		t.Fatalf("ParseDump: %v", err)
	}
	if got, want := state.Peers[0].LatestHandshake, time.Unix(1752900000, 0).UTC(); !got.Equal(want) {
		t.Errorf("LatestHandshake = %v, want %v", got, want)
	}
}

// The traffic counters and endpoint answer "does this device actually use the
// hub"; the bot's device screens are built on them.
func TestParseDumpReadsEndpointAndTraffic(t *testing.T) {
	t.Parallel()
	dump := strings.Replace(syntheticDump,
		syntheticPeerPublicKey+"\t(none)\t(none)\t10.80.0.2/32\t0\t0\t0\toff",
		syntheticPeerPublicKey+"\t(none)\t203.0.113.7:33333\t10.80.0.2/32\t1752900000\t1024\t2048\toff", 1)
	state, err := ParseDump(dump)
	if err != nil {
		t.Fatalf("ParseDump: %v", err)
	}
	peer := state.Peers[0]
	if peer.Endpoint != "203.0.113.7:33333" {
		t.Errorf("Endpoint = %q", peer.Endpoint)
	}
	if peer.RxBytes != 1024 || peer.TxBytes != 2048 {
		t.Errorf("traffic = %d/%d, want 1024/2048", peer.RxBytes, peer.TxBytes)
	}

	// The (none) endpoint of a never-connected peer stays empty.
	original, err := ParseDump(syntheticDump)
	if err != nil {
		t.Fatal(err)
	}
	if original.Peers[0].Endpoint != "" {
		t.Errorf("a never-connected peer must have no endpoint, got %q", original.Peers[0].Endpoint)
	}
}

func TestParseDumpHandlesAnInterfaceWithNoPeers(t *testing.T) {
	t.Parallel()
	header := strings.SplitN(syntheticDump, "\n", 2)[0]
	state, err := ParseDump(header + "\n")
	if err != nil {
		t.Fatalf("ParseDump: %v", err)
	}
	if len(state.Peers) != 0 {
		t.Errorf("expected no peers, got %d", len(state.Peers))
	}
}

func TestParseDumpRejectsMalformedOutput(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"empty":              "",
		"short header":       "key\tpub\n",
		"non-numeric port":   "key\tpub\tnotaport\n",
		"truncated peer":     syntheticDump[:strings.Index(syntheticDump, "\n")+1] + "onlyonefield\n",
		"bad handshake time": strings.Replace(syntheticDump, "10.80.0.2/32\t0", "10.80.0.2/32\tsoon", 1),
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseDump(input); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
