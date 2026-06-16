// Package inspect uses go-containerregistry (ggcr) to talk to a registry over
// stable APIs only: resolve a reference to a digest, read the image config to
// evaluate the non-root policy, and check for the *presence* of cosign
// signature and SBOM-attestation OCI artifacts.
//
// Everything here is Tier 1: it establishes presence, never cryptographic
// validity. Cryptographic verification lives in internal/verify.
package inspect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// in-toto predicate types. cosign maps its --type shorthands onto these URIs.
// We filter strictly by predicate type so the coexisting `vuln` attestation
// can never be mistaken for the SBOM one (build spec §3, §5).
const (
	// PredicateSPDX is the predicate type cosign uses for --type spdxjson.
	PredicateSPDX = "https://spdx.dev/Document"
	// PredicateVuln is the predicate type cosign uses for --type vuln.
	PredicateVuln = "https://cosign.sigstore.dev/attestation/vuln/v1"
	// PredicateCosignSign is the predicate type cosign v3 uses to represent an
	// image signature, which is itself stored as a DSSE in-toto statement
	// (not a legacy messageSignature) in a sigstore bundle referrer.
	PredicateCosignSign = "https://sigstore.dev/cosign/sign/v1"
)

// bundleMediaTypePrefix is the artifact/media type prefix cosign v3 (and
// sigstore-go) use for protobuf bundles attached via the OCI referrers API.
// forge's pipeline produces bundles of this family (empirically v0.3); we
// match by prefix so future minor bundle versions still classify.
const bundleMediaTypePrefix = "application/vnd.dev.sigstore.bundle"

// Image bundles the resolved references and config that both the Tier 1
// presence checks and the Tier 2 crypto checks need.
type Image struct {
	// Ref is the parsed input reference.
	Ref name.Reference
	// Digest is the resolved manifest digest.
	Digest v1.Hash
	// Config is the image config file (holds the User field).
	Config *v1.ConfigFile

	opts []remote.Option
}

// Options controls how inspect talks to the registry.
type Options struct {
	// Keychain resolves registry credentials. Defaults to the ambient
	// docker keychain when nil.
	Keychain authn.Keychain
}

func (o Options) remoteOpts(ctx context.Context) []remote.Option {
	kc := o.Keychain
	if kc == nil {
		kc = authn.DefaultKeychain
	}
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(kc),
		remote.WithUserAgent("muster"),
	}
}

// Resolve parses the reference, confirms the image exists in the registry,
// and fetches its config. Any failure here is operational (the image could
// not be evaluated), not a policy failure.
func Resolve(ctx context.Context, refStr string, o Options) (*Image, error) {
	ref, err := name.ParseReference(refStr)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", refStr, err)
	}

	opts := o.remoteOpts(ctx)

	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("fetch %q: %w", refStr, err)
	}

	img, err := desc.Image()
	if err != nil {
		return nil, fmt.Errorf("read image %q: %w", refStr, err)
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("compute digest for %q: %w", refStr, err)
	}

	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read config for %q: %w", refStr, err)
	}

	return &Image{Ref: ref, Digest: digest, Config: cfg, opts: opts}, nil
}

// ConfigUser returns the User field from the image config.
func (img *Image) ConfigUser() string {
	if img.Config == nil {
		return ""
	}
	return img.Config.Config.User
}

// IsNonRoot reports whether a container User value runs as a non-root user.
// Fail closed: an unset user defaults to root, and any value resolving to UID
// 0 or the name "root" is root. A "uid:gid" form is judged on its UID part.
func IsNonRoot(user string) bool {
	u := strings.TrimSpace(user)
	if u == "" {
		return false
	}
	// "uid:gid" or "user:group" — the user is the part before the colon.
	if i := strings.IndexByte(u, ':'); i >= 0 {
		u = u[:i]
	}
	u = strings.TrimSpace(u)
	switch u {
	case "", "0", "root":
		return false
	default:
		return true
	}
}

// Artifacts summarizes the cosign/sigstore artifacts attached to the image
// digest via the OCI referrers API. It records presence and retains the raw
// sigstore bundle bytes so Tier 2 (internal/verify) can cryptographically
// verify them. Nothing here establishes validity.
type Artifacts struct {
	// Signature is true if a sigstore bundle carrying an image signature is
	// attached.
	Signature bool
	// Predicates is the set of in-toto predicate types found across attached
	// DSSE attestation bundles, e.g. PredicateSPDX, PredicateVuln.
	Predicates map[string]bool
	// SignatureBundle is the raw sigstore bundle JSON for the image signature,
	// or nil if absent.
	SignatureBundle []byte
	// AttestationBundles maps an in-toto predicate type to the raw sigstore
	// bundle JSON of the attestation carrying it.
	AttestationBundles map[string][]byte
}

// HasAttestation reports whether an attestation with the given predicate type
// is present.
func (a *Artifacts) HasAttestation(predicateType string) bool {
	return a.Predicates[predicateType]
}

// HasSBOMAttestation reports whether an SPDX SBOM attestation is present,
// filtered strictly by predicate type so the coexisting vuln attestation is
// never accepted in its place.
func (a *Artifacts) HasSBOMAttestation() bool {
	return a.HasAttestation(PredicateSPDX)
}

// SBOMBundle returns the raw sigstore bundle JSON for the SPDX SBOM
// attestation, or nil if absent.
func (a *Artifacts) SBOMBundle() []byte {
	return a.AttestationBundles[PredicateSPDX]
}

// DiscoverArtifacts walks the OCI referrers of the image digest once,
// classifying each attached sigstore bundle as either an image signature or a
// DSSE attestation (recording its predicate type). This is the convention
// cosign v3 / forge uses; the legacy .sig/.att tag scheme is intentionally
// not consulted.
func (img *Image) DiscoverArtifacts(ctx context.Context) (*Artifacts, error) {
	out := &Artifacts{Predicates: map[string]bool{}, AttestationBundles: map[string][]byte{}}

	dig := img.Ref.Context().Digest(img.Digest.String())
	idx, err := remote.Referrers(dig, img.withContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("list referrers: %w", err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read referrers index: %w", err)
	}

	// Note: GHCR reports the referrer's top-level artifactType as the empty
	// placeholder, so we cannot filter on manifest.Manifests[].ArtifactType.
	// classifyBundle fetches each referrer and is authoritative: it returns
	// an error for anything that is not a sigstore bundle, which we skip.
	for _, ref := range manifest.Manifests {
		kind, predicate, raw, err := img.classifyBundle(ctx, ref.Digest.String())
		if err != nil {
			// A referrer we cannot parse/classify is skipped.
			continue
		}
		switch kind {
		case bundleSignature:
			out.Signature = true
			out.SignatureBundle = raw
		case bundleAttestation:
			if predicate != "" {
				out.Predicates[predicate] = true
				out.AttestationBundles[predicate] = raw
			}
		}
	}
	return out, nil
}

type bundleKind int

const (
	bundleUnknown bundleKind = iota
	bundleSignature
	bundleAttestation
)

// classifyBundle fetches a referrer manifest, reads its single sigstore bundle
// layer, and classifies it. For attestations it decodes the DSSE in-toto
// statement to recover the predicate type. No signature verification happens
// here — Tier 1 establishes presence only.
func (img *Image) classifyBundle(ctx context.Context, digest string) (bundleKind, string, []byte, error) {
	sub := img.Ref.Context().Digest(digest)
	rimg, err := remote.Image(sub, img.withContext(ctx)...)
	if err != nil {
		return bundleUnknown, "", nil, err
	}
	layers, err := rimg.Layers()
	if err != nil {
		return bundleUnknown, "", nil, err
	}

	for _, l := range layers {
		mt, err := l.MediaType()
		if err != nil {
			continue
		}
		if !strings.HasPrefix(string(mt), bundleMediaTypePrefix) {
			continue
		}
		raw, err := readLayer(l)
		if err != nil {
			return bundleUnknown, "", nil, err
		}
		kind, predicate, err := classifyBundleJSON(raw)
		return kind, predicate, raw, err
	}
	return bundleUnknown, "", nil, fmt.Errorf("no sigstore bundle layer in referrer %s", digest)
}

// sigstoreBundle is the minimal shape of a sigstore protobuf bundle (JSON
// form) needed to tell a signature from a DSSE attestation.
type sigstoreBundle struct {
	MessageSignature *json.RawMessage `json:"messageSignature"`
	DSSEEnvelope     *dsseEnvelope    `json:"dsseEnvelope"`
}

// dsseEnvelope is the minimal shape of a DSSE envelope carried in a bundle.
type dsseEnvelope struct {
	Payload string `json:"payload"`
}

// intotoStatement is the minimal shape needed to read the predicate type.
type intotoStatement struct {
	PredicateType string `json:"predicateType"`
}

// classifyBundleJSON inspects a bundle's JSON to determine whether it is an
// image signature or a DSSE attestation, and for attestations returns the
// in-toto predicate type.
//
// cosign v3 represents the image signature itself as a DSSE in-toto statement
// with predicate type PredicateCosignSign, so a bundle can be a signature even
// though it carries a dsseEnvelope. We also still recognize the legacy
// messageSignature form for forward/backward compatibility.
func classifyBundleJSON(raw []byte) (bundleKind, string, error) {
	var b sigstoreBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return bundleUnknown, "", err
	}
	if b.MessageSignature != nil {
		return bundleSignature, "", nil
	}
	if b.DSSEEnvelope != nil {
		payload, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Payload)
		if err != nil {
			return bundleUnknown, "", err
		}
		var stmt intotoStatement
		if err := json.Unmarshal(payload, &stmt); err != nil {
			return bundleUnknown, "", err
		}
		if stmt.PredicateType == PredicateCosignSign {
			return bundleSignature, "", nil
		}
		return bundleAttestation, stmt.PredicateType, nil
	}
	return bundleUnknown, "", fmt.Errorf("bundle is neither a signature nor a DSSE attestation")
}

// readLayer reads a layer's uncompressed bytes fully.
func readLayer(l v1.Layer) ([]byte, error) {
	rc, err := l.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// withContext returns the stored remote options rebound to ctx.
func (img *Image) withContext(ctx context.Context) []remote.Option {
	return append([]remote.Option{remote.WithContext(ctx)}, img.opts...)
}
