package main

import (
	"fmt"
	"os"
	"os/exec"
)

const installHint = "install with: curl -fsSL https://get.example.invalid/install.sh | sh"

func main() {
	if _, err := exec.LookPath("tool"); err != nil {
		fmt.Println("tool not found; " + installHint)
		fmt.Fprintln(os.Stderr, "or: wget -qO- https://get.example.invalid/install.sh | bash")
		os.Exit(1)
	}
	out, _ := exec.Command("git", "rev-parse", "HEAD").Output()
	fmt.Println(string(out))
}
