package linux

import (
	"strings"
	"testing"
	"time"
)

// realDump was captured from `awg show awg0 dump` on the lab host: one interface line
// carrying the obfuscation parameters, then one peer that has never handshaken.
const realDump = "YK8abDsljvw7F3rfkYsup5IR39Q6gCcz/d5t0828jX0=\t6OUoSDjcaLflZn3V7U3aO6eW1Mn5HE4xPJYmzoVvnhU=\t51820\t4\t64\t256\t15\t30\t0\t0\t12345\t23456\t34567\t45678\t(null)\t(null)\t(null)\t(null)\t(null)\toff\n" +
	"aYo1x9b951yd4mtMeKkW/vyOJvU08j2UU96u/Ve9QWA=\t(none)\t(none)\t10.80.0.2/32\t0\t0\t0\toff\n"

func TestParseDump(t *testing.T) {
	t.Parallel()
	state, err := ParseDump(realDump)
	if err != nil {
		t.Fatalf("ParseDump: %v", err)
	}

	if !state.Exists {
		t.Error("Exists = false")
	}
	if want := "6OUoSDjcaLflZn3V7U3aO6eW1Mn5HE4xPJYmzoVvnhU="; state.PublicKey != want {
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
	dump := strings.Replace(realDump, "10.80.0.2/32\t0\t0\t0", "10.80.0.2/32\t1752900000\t1024\t2048", 1)
	state, err := ParseDump(dump)
	if err != nil {
		t.Fatalf("ParseDump: %v", err)
	}
	if got, want := state.Peers[0].LatestHandshake, time.Unix(1752900000, 0).UTC(); !got.Equal(want) {
		t.Errorf("LatestHandshake = %v, want %v", got, want)
	}
}

func TestParseDumpHandlesAnInterfaceWithNoPeers(t *testing.T) {
	t.Parallel()
	header := strings.SplitN(realDump, "\n", 2)[0]
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
		"truncated peer":     realDump[:strings.Index(realDump, "\n")+1] + "onlyonefield\n",
		"bad handshake time": strings.Replace(realDump, "10.80.0.2/32\t0", "10.80.0.2/32\tsoon", 1),
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
