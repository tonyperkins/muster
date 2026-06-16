package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/tonyperkins/muster/internal/inspect"
	"github.com/tonyperkins/muster/internal/report"
	"github.com/tonyperkins/muster/internal/verify"
)

// verifyFlags holds the parsed flag values for the verify command.
type verifyFlags struct {
	requireSignature bool
	requireSBOM      bool
	requireNonroot   bool

	certIdentity       string
	certIdentityRegexp string
	certOIDCIssuer     string
	key                string

	json             bool
	insecureSkipTlog bool
}

func newVerifyCmd() *cobra.Command {
	f := &verifyFlags{}

	cmd := &cobra.Command{
		Use:   "verify <image-ref>",
		Short: "Verify an image against the supply-chain baseline",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(cmd.Context(), args[0], f)
		},
	}

	fl := cmd.Flags()
	fl.BoolVar(&f.requireSignature, "require-signature", true, "fail if signature is absent/invalid")
	fl.BoolVar(&f.requireSBOM, "require-sbom", true, "fail if SBOM attestation is absent/invalid")
	fl.BoolVar(&f.requireNonroot, "require-nonroot", true, "fail if image runs as root")
	fl.StringVar(&f.certIdentity, "certificate-identity", "", "expected signer identity (keyless verification)")
	fl.StringVar(&f.certIdentityRegexp, "certificate-identity-regexp", "", "expected signer identity as a regexp (keyless verification)")
	fl.StringVar(&f.certOIDCIssuer, "certificate-oidc-issuer", "", "expected OIDC issuer (keyless verification)")
	fl.StringVar(&f.key, "key", "", "path/URL to public key (key-based verification, alt to keyless)")
	fl.BoolVar(&f.json, "json", false, "emit machine-readable JSON instead of text")
	fl.BoolVar(&f.insecureSkipTlog, "insecure-skip-tlog", false, "skip transparency-log verification (discouraged)")

	return cmd
}

func init() {
	rootCmd.AddCommand(newVerifyCmd())
}

// runVerify performs the gate evaluation. It always emits a result and sets
// the package-level exitCode; it only returns an error for problems cobra
// should report as usage failures.
func runVerify(ctx context.Context, ref string, f *verifyFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}

	if f.key != "" {
		// Key-based verification is a different trust model from forge's
		// keyless flow and is intentionally out of scope for v1. Fail with a
		// clear usage error rather than silently ignoring the flag.
		return fmt.Errorf("--key (key-based verification) is not implemented in v1; " +
			"use keyless verification with --certificate-identity(-regexp) and --certificate-oidc-issuer")
	}

	if f.insecureSkipTlog {
		fmt.Fprintln(os.Stderr,
			"WARNING: --insecure-skip-tlog is set; transparency-log verification is DISABLED. "+
				"This weakens signature trust and must not be used in production gates.")
	}

	res := &report.Result{Image: ref}

	img, err := inspect.Resolve(ctx, ref, inspect.Options{})
	if err != nil {
		res.OperationalError = err.Error()
		emit(res, f.json)
		exitCode = res.ExitCode()
		return nil
	}
	res.Digest = img.Digest.String()

	// --- non-root policy (Tier 1, config-based) ---
	user := img.ConfigUser()
	nonroot := inspect.IsNonRoot(user)
	res.Add(report.Check{
		Name:     "nonroot",
		Required: f.requireNonroot,
		Status:   passFail(nonroot),
		Detail:   nonRootDetail(user, nonroot),
	})

	// --- artifact presence (Tier 1): one referrers walk classifies all ---
	arts, err := img.DiscoverArtifacts(ctx)
	if err != nil {
		res.OperationalError = fmt.Sprintf("discover artifacts: %v", err)
		emit(res, f.json)
		exitCode = res.ExitCode()
		return nil
	}

	// Decide tier: if keyless identity flags are supplied, perform Tier 2
	// cryptographic verification; otherwise report Tier 1 presence only.
	vopts := verify.Options{
		CertIdentity:       f.certIdentity,
		CertIdentityRegexp: f.certIdentityRegexp,
		CertOIDCIssuer:     f.certOIDCIssuer,
		SkipTlog:           f.insecureSkipTlog,
	}

	if vopts.KeylessConfigured() {
		v, err := verify.New(img.Digest, vopts)
		if err != nil {
			res.OperationalError = fmt.Sprintf("initialize verifier: %v", err)
			emit(res, f.json)
			exitCode = res.ExitCode()
			return nil
		}
		addCryptoCheck(res, "signature", f.requireSignature, arts.Signature, arts.SignatureBundle, v)
		addCryptoCheck(res, "sbom", f.requireSBOM, arts.HasSBOMAttestation(), arts.SBOMBundle(), v)
	} else {
		addPresenceCheck(res, "signature", f.requireSignature, arts.Signature,
			"signature bundle present (presence only; not cryptographically verified)",
			"no signature artifact found for digest")
		addPresenceCheck(res, "sbom", f.requireSBOM, arts.HasSBOMAttestation(),
			"SPDX SBOM attestation present (presence only; not cryptographically verified)",
			"no SPDX SBOM attestation found for digest")
	}

	emit(res, f.json)
	exitCode = res.ExitCode()
	return nil
}

// addPresenceCheck records a PRESENT/ABSENT check from an already-determined
// presence boolean. Tier 1 never claims cryptographic validity.
func addPresenceCheck(res *report.Result, name string, required, present bool, presentDetail, absentDetail string) {
	status := report.StatusAbsent
	detail := absentDetail
	if present {
		status = report.StatusPresent
		detail = presentDetail
	}
	res.Add(report.Check{Name: name, Required: required, Status: status, Detail: detail})
}

// addCryptoCheck records a Tier 2 check: PASS only if the artifact is present
// AND cryptographically verifies against the configured identity; FAIL if
// absent or invalid. Fail closed.
func addCryptoCheck(res *report.Result, name string, required, present bool, raw []byte, v *verify.Verifier) {
	if !present {
		res.Add(report.Check{Name: name, Required: required, Status: report.StatusFail,
			Detail: "no " + name + " artifact found for digest"})
		return
	}
	if err := v.VerifyBundle(raw); err != nil {
		res.Add(report.Check{Name: name, Required: required, Status: report.StatusFail,
			Detail: "verification failed: " + err.Error()})
		return
	}
	res.Add(report.Check{Name: name, Required: required, Status: report.StatusPass,
		Detail: "cryptographically verified against signer identity"})
}

func passFail(ok bool) report.Status {
	if ok {
		return report.StatusPass
	}
	return report.StatusFail
}

func nonRootDetail(user string, nonroot bool) string {
	shown := user
	if shown == "" {
		shown = "<unset>"
	}
	if nonroot {
		return fmt.Sprintf("runs as non-root user %q", shown)
	}
	return fmt.Sprintf("runs as root (User=%q; unset/0/root fails closed)", shown)
}

func emit(res *report.Result, asJSON bool) {
	if asJSON {
		_ = res.WriteJSON(os.Stdout)
		return
	}
	_ = res.WriteText(os.Stdout)
}
