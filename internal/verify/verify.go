// Package verify performs Tier 2 cryptographic verification of cosign v3
// keyless signatures and SPDX SBOM attestations using sigstore-go.
//
// It verifies sigstore protobuf bundles (the format forge attaches via the
// OCI referrers API) against an expected keyless signer identity and OIDC
// issuer, binding each bundle to the image digest. Rekor transparency-log
// inclusion is enforced by default; it can be disabled only via the explicit,
// loud --insecure-skip-tlog path (see Options.SkipTlog).
package verify

import (
	"encoding/hex"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	sg "github.com/sigstore/sigstore-go/pkg/verify"
)

// Options configures keyless verification. forge signs keyless (GitHub OIDC →
// Fulcio → Rekor); key-based verification is intentionally not implemented in
// v1 (see cmd handling of --key).
type Options struct {
	// CertIdentity is the exact expected signer SAN (mutually usable with
	// CertIdentityRegexp; at least one is required).
	CertIdentity string
	// CertIdentityRegexp is a regexp the signer SAN must match.
	CertIdentityRegexp string
	// CertOIDCIssuer is the exact expected OIDC issuer.
	CertOIDCIssuer string
	// CertOIDCIssuerRegexp is a regexp the OIDC issuer must match.
	CertOIDCIssuerRegexp string
	// SkipTlog disables transparency-log (and observer-timestamp)
	// verification. Discouraged; defaults off.
	SkipTlog bool
}

// KeylessConfigured reports whether enough identity flags were supplied to
// attempt keyless verification. Both an issuer (value or regexp) and an
// identity (value or regexp) are required.
func (o Options) KeylessConfigured() bool {
	hasIssuer := o.CertOIDCIssuer != "" || o.CertOIDCIssuerRegexp != ""
	hasIdentity := o.CertIdentity != "" || o.CertIdentityRegexp != ""
	return hasIssuer && hasIdentity
}

// Verifier verifies sigstore bundles against a fixed identity policy and image
// digest. Construct it once per image with New, then call VerifyBundle for the
// signature and each attestation.
type Verifier struct {
	sev            *sg.Verifier
	identity       sg.PolicyOption
	digestAlg      string
	artifactDigest []byte
}

// New builds a Verifier. It fetches the Sigstore public-good trusted root via
// TUF (network), which is cached on disk for subsequent runs.
func New(imageDigest v1.Hash, o Options) (*Verifier, error) {
	if !o.KeylessConfigured() {
		return nil, fmt.Errorf("keyless verification requires both an OIDC issuer and a certificate identity")
	}

	tr, err := root.NewLiveTrustedRoot(tuf.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("fetch sigstore trusted root: %w", err)
	}

	var vopts []sg.VerifierOption
	if o.SkipTlog {
		// Insecure path: no Rekor inclusion, no observer timestamps; cert
		// validity is checked against the current time only.
		vopts = []sg.VerifierOption{
			sg.WithCurrentTime(),
			sg.WithNoObserverTimestamps(),
		}
	} else {
		// Secure default: require SCT, Rekor inclusion, and an observer
		// (integrated) timestamp.
		vopts = []sg.VerifierOption{
			sg.WithSignedCertificateTimestamps(1),
			sg.WithObserverTimestamps(1),
			sg.WithTransparencyLog(1),
		}
	}
	sev, err := sg.NewVerifier(tr, vopts...)
	if err != nil {
		return nil, fmt.Errorf("build verifier: %w", err)
	}

	// NewShortCertificateIdentity(issuer, issuerRegex, sanValue, sanRegex).
	id, err := sg.NewShortCertificateIdentity(
		o.CertOIDCIssuer, o.CertOIDCIssuerRegexp,
		o.CertIdentity, o.CertIdentityRegexp,
	)
	if err != nil {
		return nil, fmt.Errorf("build identity policy: %w", err)
	}

	db, err := hex.DecodeString(imageDigest.Hex)
	if err != nil {
		return nil, fmt.Errorf("decode image digest: %w", err)
	}

	return &Verifier{
		sev:            sev,
		identity:       sg.WithCertificateIdentity(id),
		digestAlg:      imageDigest.Algorithm,
		artifactDigest: db,
	}, nil
}

// VerifyBundle cryptographically verifies a raw sigstore bundle against the
// configured identity policy, binding it to the image digest. It returns nil
// if and only if verification succeeds.
func (v *Verifier) VerifyBundle(raw []byte) error {
	if len(raw) == 0 {
		return fmt.Errorf("empty bundle")
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return fmt.Errorf("parse sigstore bundle: %w", err)
	}
	policy := sg.NewPolicy(
		sg.WithArtifactDigest(v.digestAlg, v.artifactDigest),
		v.identity,
	)
	if _, err := v.sev.Verify(&b, policy); err != nil {
		return err
	}
	return nil
}
