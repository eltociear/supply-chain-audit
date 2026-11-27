package main

// a command's own `upgrade` subcommand: runs the vendor's installer in the user's terminal
import (
	"bytes"
	"io"
	"net/http"
	"os"
	"os/exec"
)

func installer(cmd string) error {
	res, err := http.Get("https://example.invalid/install")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var script bytes.Buffer
	if _, err := io.Copy(&script, res.Body); err != nil {
		return err
	}
	c := exec.Command("sh", "-c", script.String())
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}
