// Package report defines the structured verification result, the exit-code
// contract, and human-readable / JSON rendering. It is deliberately free of
// registry or crypto logic so it can be unit-tested in isolation.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Exit codes form the gate contract (see build spec §7). The distinction
// between a policy failure (1) and an operational error (2) is intentional:
// a CI job should treat "this image is non-compliant" differently from
// "I could not evaluate the image at all".
const (
	// ExitPass means all required checks passed.
	ExitPass = 0
	// ExitPolicyFailure means one or more required checks failed
	// (unsigned, no SBOM, runs as root, invalid attestation).
	ExitPolicyFailure = 1
	// ExitOperationalError means muster could not evaluate the image
	// (ref not found, registry auth failure, network error, bad input).
	ExitOperationalError = 2
)

// Status is the outcome of a single check. We deliberately separate "present"
// from "verified": a presence check (Tier 1) must never claim cryptographic
// validity it did not establish.
type Status string

const (
	// StatusPass means the check was evaluated and satisfied.
	StatusPass Status = "PASS"
	// StatusFail means the check was evaluated and not satisfied.
	StatusFail Status = "FAIL"
	// StatusPresent means an artifact exists but was not cryptographically
	// verified (Tier 1 presence-only).
	StatusPresent Status = "PRESENT"
	// StatusAbsent means an artifact does not exist.
	StatusAbsent Status = "ABSENT"
	// StatusSkipped means the check was not requested by the caller.
	StatusSkipped Status = "SKIPPED"
)

// Check is one line item in the verification result.
type Check struct {
	// Name is a short identifier, e.g. "nonroot", "signature", "sbom".
	Name string `json:"name"`
	// Status is the outcome.
	Status Status `json:"status"`
	// Required indicates whether this check gates the exit code.
	Required bool `json:"required"`
	// Detail is a human-readable explanation of the outcome.
	Detail string `json:"detail,omitempty"`
}

// gating reports whether this check, given its status, should cause a
// policy failure. Only required checks gate. PASS and PRESENT are acceptable
// outcomes; FAIL and ABSENT are not. SKIPPED never gates.
func (c Check) gating() bool {
	if !c.Required {
		return false
	}
	switch c.Status {
	case StatusFail, StatusAbsent:
		return true
	default:
		return false
	}
}

// Result is the complete outcome for one image reference.
type Result struct {
	// Image is the reference as supplied by the caller.
	Image string `json:"image"`
	// Digest is the resolved manifest digest, when known.
	Digest string `json:"digest,omitempty"`
	// Checks is the ordered list of evaluated checks.
	Checks []Check `json:"checks"`
	// OperationalError, when non-empty, indicates muster could not evaluate
	// the image at all. It maps to ExitOperationalError and takes precedence
	// over any policy outcome.
	OperationalError string `json:"operational_error,omitempty"`
}

// Add appends a check to the result.
func (r *Result) Add(c Check) {
	r.Checks = append(r.Checks, c)
}

// ExitCode maps the result to the gate's exit-code contract. Operational
// errors win over policy failures, which win over success. This is a pure
// function of the result so it can be table-tested directly.
func (r *Result) ExitCode() int {
	if r.OperationalError != "" {
		return ExitOperationalError
	}
	for _, c := range r.Checks {
		if c.gating() {
			return ExitPolicyFailure
		}
	}
	return ExitPass
}

// WriteJSON renders the result as indented JSON.
func (r *Result) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText renders a human-readable summary. Every check is printed
// regardless of exit code so a failing gate still explains itself.
func (r *Result) WriteText(w io.Writer) error {
	var b strings.Builder

	fmt.Fprintf(&b, "image:  %s\n", r.Image)
	if r.Digest != "" {
		fmt.Fprintf(&b, "digest: %s\n", r.Digest)
	}

	if r.OperationalError != "" {
		fmt.Fprintf(&b, "\nERROR: %s\n", r.OperationalError)
	}

	if len(r.Checks) > 0 {
		b.WriteString("\nchecks:\n")
		for _, c := range r.Checks {
			req := "optional"
			if c.Required {
				req = "required"
			}
			fmt.Fprintf(&b, "  [%-7s] %-12s (%s)", c.Status, c.Name, req)
			if c.Detail != "" {
				fmt.Fprintf(&b, "  %s", c.Detail)
			}
			b.WriteString("\n")
		}
	}

	switch r.ExitCode() {
	case ExitPass:
		b.WriteString("\nresult: PASS — all required checks satisfied\n")
	case ExitPolicyFailure:
		b.WriteString("\nresult: FAIL — one or more required checks did not pass\n")
	case ExitOperationalError:
		b.WriteString("\nresult: ERROR — could not evaluate image\n")
	}

	_, err := io.WriteString(w, b.String())
	return err
}
