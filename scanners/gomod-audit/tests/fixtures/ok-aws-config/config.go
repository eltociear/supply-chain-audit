package awscfg

import (
	"net/http"
	"os"
	"path/filepath"
)

var defaultPath = filepath.Join(home(), ".aws/credentials")

func home() string { h, _ := os.UserHomeDir(); return h }

// Load reads the shared credentials file and calls STS.
func Load() error {
	_, _ = os.ReadFile(defaultPath)
	req, _ := http.NewRequest("POST", "https://sts.amazonaws.com/", nil)
	_, err := http.DefaultClient.Do(req)
	return err
}

// metadata endpoint
const imds = "http://169.254.169.254/latest/meta-data/"
