package runner

import (
	"context"
	"os"
	"os/exec"
)

// Run executes a user-supplied hook command through the shell.
func Run(ctx context.Context, hook string) error {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", hook)
	cmd.Env = append(os.Environ(), "HOOK=1")
	cmd.Stdout = os.Stdout
	return cmd.Run()
}
