# muster

**A single static binary that verifies a pushed container image meets a supply-chain baseline, as a CI gate.** It checks that an image runs as a non-root user and that the cosign signature and SPDX SBOM attestation produced by [`forge`](https://github.com/tonyperkins/forge) are attached — exiting non-zero if not.

`muster` deliberately does **not** build images, harden them, sign them, generate SBOMs, or scan for CVEs. Those are the jobs of `forge`, `cosign`, [`syft`](https://github.com/anchore/syft), and [`grype`](https://github.com/anchore/grype) respectively. `muster` only *verifies*.

## What it is (and what it isn't)

`forge`'s own GitHub Actions pipeline already runs `cosign verify` + `cosign verify-attestation` as a hard gate. `muster` does **not** add a capability `forge` lacks. Its value is repackaging that same enforcement as one portable, dependency-free binary that *any consumer of the image* can run anywhere — in a different pipeline, on a workstation, or in a minimal admission step — without installing the cosign CLI or its dependency tree.

Think of it as **the portable binary version of forge's gate**, built on the same libraries the real tooling uses:

- [`go-containerregistry`](https://github.com/google/go-containerregistry) (what crane/cosign/ko are built on) for registry, manifest, and config access.
- [`sigstore-go`](https://github.com/sigstore/sigstore-go) for cryptographic signature/attestation verification (Tier 2 — see Status).

## Why Go here

Not for speed. For **distribution and typed library access**: `muster` compiles to a single static binary (`CGO_ENABLED=0`, no libc, no runtime) that drops into any pipeline or minimal image, and it links the same Go libraries cosign/crane use instead of shelling out to their CLIs. That deployment property is the entire reason this is Go rather than a Python script.

## Status: what is verified vs merely present

`muster` is built in tiers, **both implemented**. The tier used depends on whether you supply keyless identity flags:

| Check | Without identity flags (Tier 1) | With `--certificate-identity(-regexp)` + `--certificate-oidc-issuer` (Tier 2) |
|-------|--------------------------------|-------------------------------------------------------------------------------|
| Image resolves to a digest & exists | yes | yes |
| Runs as non-root user | **verified** (PASS/FAIL) | verified |
| cosign signature | **present / absent** | **cryptographically verified** (keyless identity + Rekor inclusion) |
| SPDX SBOM attestation | **present / absent** | **cryptographically verified** (signed in-toto/DSSE, predicate-filtered) |

A `PRESENT` result means the artifact exists and was classified by predicate type — it does **not** mean it was cryptographically verified. `muster` never labels a check "verified" when it has only confirmed presence. Tier 2 verification binds each bundle to the image digest and checks it against the expected signer identity and OIDC issuer, with Rekor transparency-log inclusion enforced by default.

Tier 2 has been verified end-to-end against the live fixture `ghcr.io/tonyperkins/uptime-kuma:latest` (signer SAN `https://github.com/tonyperkins/forge/.github/workflows/forge.yml@refs/heads/main`, issuer `https://token.actions.githubusercontent.com`).

## Limitations

- **Tier 1 (presence) vs Tier 2 (cryptographic).** If you do not supply keyless identity flags, `muster` reports signature/SBOM as `PRESENT`/`ABSENT` only — it has *not* checked them against a signer identity or the transparency log. Supply `--certificate-identity(-regexp)` and `--certificate-oidc-issuer` to get full cryptographic verification.
- **Keyless only.** Tier 2 implements keyless (Fulcio/Rekor) verification, which is what `forge` produces. `--key` (key-based verification) is intentionally **not** implemented in v1 and exits with a clear error rather than silently passing.
- **`vuln` attestation not verified.** `forge` also emits a grype `vuln` attestation; v1 neither requires nor verifies it. A `--require-vuln-attestation` flag is a clean future extension.
- **Artifact convention.** `forge` (cosign v3, keyless) attaches its signature, SBOM, and vuln artifacts as **OCI 1.1 referrers** in the [sigstore protobuf bundle](https://github.com/sigstore/protobuf-specs) format (`application/vnd.dev.sigstore.bundle.v0.3+json`), *not* the legacy `sha256-<digest>.sig`/`.att` tag scheme. `muster` discovers artifacts via the referrers API and classifies each bundle by its in-toto predicate type:
  - signature → `https://sigstore.dev/cosign/sign/v1` (cosign v3 stores the image signature itself as a DSSE statement)
  - SBOM → `https://spdx.dev/Document`
  - vuln → `https://cosign.sigstore.dev/attestation/vuln/v1`
  The legacy tag scheme is intentionally not consulted. Images signed with older cosign that use only the tag scheme would currently report `ABSENT`.
- **SBOM is filtered strictly by predicate type.** The coexisting `vuln` attestation `forge` also emits is never mistaken for the SBOM. Verifying the `vuln` attestation is out of scope for v1 (a clean future `--require-vuln-attestation` flag).
- **No CVE scanning, SBOM generation, signing, or image building.** Out of scope by design.

## Install / build

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o muster .
```

This produces a fully static binary (verified in CI with `ldd`). Pinned toolchain: Go 1.26. Key dependencies: `go-containerregistry` and `cobra` (see `go.mod`); `govulncheck` runs in CI.

## Usage

```
muster verify <image-ref> [flags]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--require-signature` | `true` | fail if signature is absent/invalid |
| `--require-sbom` | `true` | fail if SBOM attestation is absent/invalid |
| `--require-nonroot` | `true` | fail if image runs as root |
| `--certificate-identity` | | expected signer identity (keyless, Tier 2) |
| `--certificate-identity-regexp` | | expected signer identity as a regexp (keyless, Tier 2) |
| `--certificate-oidc-issuer` | | expected OIDC issuer (keyless, Tier 2) |
| `--key` | | public key for key-based verification (alt to keyless, Tier 2) |
| `--json` | `false` | machine-readable JSON output |
| `--insecure-skip-tlog` | `false` | skip transparency-log verification (**discouraged**; prints a loud warning) |

### Exit codes (the gate contract)

| Exit | Meaning |
|------|---------|
| `0` | all required checks passed |
| `1` | one or more required checks failed (unsigned, no SBOM, runs as root, invalid attestation) |
| `2` | operational error (ref not found, registry auth failure, network error, malformed input) |

Exit `1` (policy failure) and exit `2` (couldn't evaluate) are kept distinct so a CI job can treat them differently.

### Example: CI gate

```bash
muster verify ghcr.io/tonyperkins/uptime-kuma:latest \
  --certificate-identity-regexp 'https://github.com/tonyperkins/forge/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
case $? in
  0) echo "image passed the supply-chain gate" ;;
  1) echo "image FAILED policy — blocking deploy"; exit 1 ;;
  2) echo "could not evaluate image — investigate"; exit 1 ;;
esac
```

## Security notes

- Dependencies are pinned to current patched versions; `govulncheck` runs in CI.
- Transparency-log verification (Tier 2) is on by default. `--insecure-skip-tlog` exists for offline/testing only, defaults off, and prints a loud warning — skipping it is exactly the condition recent CVEs exploited.
- **Fail closed.** Any ambiguity in a required check is a FAIL: an unset user is treated as root; an unparseable artifact is invalid.

## Testing

```bash
go test ./...                 # hermetic: uses an in-process registry, no network
MUSTER_E2E=1 go test ./internal/verify -run TestE2E   # live: verifies the fixture against ghcr + Sigstore
```

The default suite is fully offline. The live end-to-end verification test is opt-in via `MUSTER_E2E=1`.

## The image

`muster`'s own container (`Dockerfile`) is multi-stage: it compiles with `CGO_ENABLED=0` and ships on `cgr.dev/chainguard/static` as a non-root, shell-less, package-manager-less image — making it a demonstration of the standard it enforces.
