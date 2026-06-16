// Command muster is a container attestation verification gate. It is a thin
// entrypoint that delegates to the cobra command tree and exits with the
// gate's contract code (0 pass, 1 policy failure, 2 operational error).
package main

import (
	"os"

	"github.com/tonyperkins/muster/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
