package inspect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestIsNonRoot(t *testing.T) {
	tests := []struct {
		user string
		want bool
	}{
		{"", false},         // unset defaults to root — fail closed
		{"0", false},        // numeric root
		{"root", false},     // named root
		{"65532", true},     // nonroot uid
		{"nonroot", true},   // named nonroot
		{"1000:1000", true}, // uid:gid nonroot
		{"0:0", false},      // uid:gid root
		{"root:root", false},
		{"  ", false},    // whitespace-only is unset
		{" 1000 ", true}, // trimmed
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("user=%q", tt.user), func(t *testing.T) {
			if got := IsNonRoot(tt.user); got != tt.want {
				t.Errorf("IsNonRoot(%q) = %v, want %v", tt.user, got, tt.want)
			}
		})
	}
}

// makeBundleJSON builds a minimal sigstore-bundle JSON of the given kind.
func sigBundleJSON(t *testing.T, predicateType string, messageSig bool) []byte {
	t.Helper()
	m := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
	}
	if messageSig {
		m["messageSignature"] = map[string]any{"signature": "Zm9v"}
	} else {
		stmt := map[string]any{
			"_type":         "https://in-toto.io/Statement/v1",
			"predicateType": predicateType,
		}
		payload, _ := json.Marshal(stmt)
		m["dsseEnvelope"] = map[string]any{
			"payloadType": "application/vnd.in-toto+json",
			"payload":     base64.StdEncoding.EncodeToString(payload),
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return raw
}

func TestClassifyBundleJSON(t *testing.T) {
	tests := []struct {
		name          string
		raw           []byte
		wantKind      bundleKind
		wantPredicate string
		wantErr       bool
	}{
		{
			name:     "cosign v3 signature (dsse cosign/sign predicate)",
			raw:      sigBundleJSON(t, PredicateCosignSign, false),
			wantKind: bundleSignature,
		},
		{
			name:     "legacy message signature",
			raw:      sigBundleJSON(t, "", true),
			wantKind: bundleSignature,
		},
		{
			name:          "spdx sbom attestation",
			raw:           sigBundleJSON(t, PredicateSPDX, false),
			wantKind:      bundleAttestation,
			wantPredicate: PredicateSPDX,
		},
		{
			name:          "vuln attestation is not a signature nor sbom",
			raw:           sigBundleJSON(t, PredicateVuln, false),
			wantKind:      bundleAttestation,
			wantPredicate: PredicateVuln,
		},
		{
			name:    "garbage json",
			raw:     []byte("{not json"),
			wantErr: true,
		},
		{
			name:    "bundle with neither signature nor dsse",
			raw:     []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, pred, err := classifyBundleJSON(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got kind=%v pred=%q", kind, pred)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if kind != tt.wantKind {
				t.Errorf("kind = %v, want %v", kind, tt.wantKind)
			}
			if pred != tt.wantPredicate {
				t.Errorf("predicate = %q, want %q", pred, tt.wantPredicate)
			}
		})
	}
}

// startRegistry spins up an in-process OCI registry and returns its host.
func startRegistry(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(registry.New())
	t.Cleanup(s.Close)
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatalf("parse registry url: %v", err)
	}
	return u.Host
}

// pushImageWithUser pushes a random single-platform image with the given
// config User and returns its reference and digest.
func pushImageWithUser(t *testing.T, host, repo, user string) (name.Reference, v1.Hash) {
	t.Helper()
	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("config file: %v", err)
	}
	cfg = cfg.DeepCopy()
	cfg.Config.User = user
	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatalf("mutate config: %v", err)
	}
	ref, err := name.ParseReference(fmt.Sprintf("%s/%s:latest", host, repo))
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("write image: %v", err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return ref, d
}

// attachBundleReferrer builds a sigstore-bundle referrer for the subject digest
// and pushes it to the registry.
func attachBundleReferrer(t *testing.T, host, repo string, subject v1.Hash, bundleJSON []byte) {
	t.Helper()
	layer := static.NewLayer(bundleJSON, types.MediaType("application/vnd.dev.sigstore.bundle.v0.3+json"))
	ref, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	ref = mutate.ConfigMediaType(ref, types.MediaType("application/vnd.oci.empty.v1+json"))
	ref = mutate.MediaType(ref, types.OCIManifestSchema1)

	subjImg := mutate.Subject(ref, v1.Descriptor{
		MediaType: types.DockerManifestSchema2,
		Digest:    subject,
	}).(v1.Image)

	d, err := subjImg.Digest()
	if err != nil {
		t.Fatalf("referrer digest: %v", err)
	}
	dref, err := name.ParseReference(fmt.Sprintf("%s/%s@%s", host, repo, d.String()))
	if err != nil {
		t.Fatalf("parse referrer ref: %v", err)
	}
	if err := remote.Write(dref, subjImg); err != nil {
		t.Fatalf("write referrer: %v", err)
	}
}

func TestResolveNonRoot(t *testing.T) {
	host := startRegistry(t)
	ctx := context.Background()

	ref, _ := pushImageWithUser(t, host, "test/nonroot", "65532:65532")
	img, err := Resolve(ctx, ref.Name(), Options{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := img.ConfigUser(); got != "65532:65532" {
		t.Errorf("ConfigUser = %q, want 65532:65532", got)
	}
	if !IsNonRoot(img.ConfigUser()) {
		t.Errorf("expected non-root for %q", img.ConfigUser())
	}
}

func TestDiscoverArtifacts(t *testing.T) {
	host := startRegistry(t)
	ctx := context.Background()

	ref, dig := pushImageWithUser(t, host, "test/full", "65532")

	// Attach all three forge-style bundles: signature, sbom, vuln.
	attachBundleReferrer(t, host, "test/full", dig, sigBundleJSON(t, PredicateCosignSign, false))
	attachBundleReferrer(t, host, "test/full", dig, sigBundleJSON(t, PredicateSPDX, false))
	attachBundleReferrer(t, host, "test/full", dig, sigBundleJSON(t, PredicateVuln, false))

	img, err := Resolve(ctx, ref.Name(), Options{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	arts, err := img.DiscoverArtifacts(ctx)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if !arts.Signature {
		t.Error("expected signature present")
	}
	if !arts.HasSBOMAttestation() {
		t.Error("expected SPDX SBOM attestation present")
	}
	if !arts.HasAttestation(PredicateVuln) {
		t.Error("expected vuln attestation present")
	}
}

func TestDiscoverArtifacts_NoReferrers(t *testing.T) {
	host := startRegistry(t)
	ctx := context.Background()

	ref, _ := pushImageWithUser(t, host, "test/bare", "root")
	img, err := Resolve(ctx, ref.Name(), Options{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	arts, err := img.DiscoverArtifacts(ctx)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if arts.Signature {
		t.Error("expected no signature")
	}
	if arts.HasSBOMAttestation() {
		t.Error("expected no sbom attestation")
	}
}
