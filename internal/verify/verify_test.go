package verify

import (
	"context"
	"os"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/tonyperkins/muster/internal/inspect"
)

func TestKeylessConfigured(t *testing.T) {
	tests := []struct {
		name string
		o    Options
		want bool
	}{
		{"nothing set", Options{}, false},
		{"issuer only", Options{CertOIDCIssuer: "https://x"}, false},
		{"identity only", Options{CertIdentity: "a@b"}, false},
		{"identity regexp only", Options{CertIdentityRegexp: ".*"}, false},
		{"issuer + identity", Options{CertOIDCIssuer: "https://x", CertIdentity: "a@b"}, true},
		{"issuer + identity regexp", Options{CertOIDCIssuer: "https://x", CertIdentityRegexp: ".*"}, true},
		{"issuer regexp + identity regexp", Options{CertOIDCIssuerRegexp: ".*", CertIdentityRegexp: ".*"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.o.KeylessConfigured(); got != tt.want {
				t.Errorf("KeylessConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRejectsUnconfiguredKeyless(t *testing.T) {
	// Should fail fast without any network access when identity is missing.
	if _, err := New(v1.Hash{}, Options{}); err == nil {
		t.Fatal("expected error for unconfigured keyless verification")
	}
}

// TestE2E exercises real verification against the live forge fixture. It is
// opt-in (set MUSTER_E2E=1) so the default `go test` run stays hermetic and
// offline per the project's testing policy. It requires network access to
// ghcr.io and the Sigstore TUF/Rekor infrastructure.
func TestE2E(t *testing.T) {
	if os.Getenv("MUSTER_E2E") == "" {
		t.Skip("set MUSTER_E2E=1 to run the live end-to-end verification test")
	}
	ctx := context.Background()
	img, err := inspect.Resolve(ctx, "ghcr.io/tonyperkins/uptime-kuma:latest", inspect.Options{})
	if err != nil {
		t.Fatalf("resolve fixture: %v", err)
	}
	arts, err := img.DiscoverArtifacts(ctx)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	v, err := New(img.Digest, Options{
		CertIdentityRegexp: `https://github.com/tonyperkins/forge/.*`,
		CertOIDCIssuer:     "https://token.actions.githubusercontent.com",
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := v.VerifyBundle(arts.SignatureBundle); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
	if err := v.VerifyBundle(arts.SBOMBundle()); err != nil {
		t.Errorf("sbom verification failed: %v", err)
	}

	// Negative: a non-matching identity must fail closed.
	vBad, err := New(img.Digest, Options{
		CertIdentityRegexp: `https://github.com/someoneelse/.*`,
		CertOIDCIssuer:     "https://token.actions.githubusercontent.com",
	})
	if err != nil {
		t.Fatalf("new verifier (bad): %v", err)
	}
	if err := vBad.VerifyBundle(arts.SignatureBundle); err == nil {
		t.Error("expected signature verification to FAIL for non-matching identity")
	}
}
