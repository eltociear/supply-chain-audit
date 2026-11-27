package codec

import (
	"os"
	"os/exec"
	"strings"
)

var registry = map[string]func([]byte) []byte{}

var gitVersion = detectGit()

func detectGit() string {
	out, err := exec.Command("git", "--version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func init() {
	registry["identity"] = func(b []byte) []byte { return b }
	if os.Getenv("CODEC_DEBUG") != "" {
		registry["debug"] = func(b []byte) []byte { return b }
	}
}
