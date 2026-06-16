// Package cmd wires the cobra CLI, flag handling, and exit-code mapping.
package cmd

import (
	"github.com/spf13/cobra"

	"github.com/tonyperkins/muster/internal/report"
)

// exitCode carries the gate result out of the command's RunE (which returns
// nil on a successfully-evaluated-but-failing policy) up to Execute.
var exitCode = report.ExitPass

var rootCmd = &cobra.Command{
	Use:   "muster",
	Short: "Verify a container image meets a supply-chain baseline (CI gate)",
	Long: `muster is a single-purpose CI gate: point it at a pushed container
image reference and it verifies the image meets a supply-chain baseline,
exiting non-zero if it does not.

It is the portable, dependency-free enforcement companion to the forge
hardening pipeline: the same signature/SBOM/non-root enforcement repackaged
as one static binary that any consumer can run anywhere, without installing
the cosign CLI or its dependency tree.

muster does not build, harden, sign, scan, or generate SBOMs — it verifies.`,
	SilenceUsage:  true,
	SilenceErrors: false,
}

// Execute runs the CLI and returns the process exit code per the gate
// contract (0 pass, 1 policy failure, 2 operational error).
func Execute() int {
	if err := rootCmd.Execute(); err != nil {
		// A returned error is a usage/operational problem (bad flags,
		// missing args). cobra has already printed it.
		return report.ExitOperationalError
	}
	return exitCode
}
