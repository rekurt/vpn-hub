package linux

import (
	"os"
	"strings"
	"testing"
)

func TestPrivilegedIntegrationTestsDoNotUseFixedTmpFiles(t *testing.T) {
	contents, err := os.ReadFile("localguard_integration_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "/tmp/localguard.nft") {
		t.Fatal("privileged integration tests must not use /tmp/localguard.nft")
	}
}
