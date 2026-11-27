package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
)

// Apply downloads a release, verifies its checksum and re-executes.
func Apply(url, sum, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != sum {
		return errors.New("checksum mismatch")
	}
	os.WriteFile(path, b, 0755)
	os.Chmod(path, 0755)
	return exec.Command(path, "--version").Run()
}
