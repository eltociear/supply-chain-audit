package sshc

import (
	"net"
	"os"
	"path/filepath"
)

// DefaultKey returns the user's default identity file.
func DefaultKey() ([]byte, error) {
	home, _ := os.UserHomeDir()
	return os.ReadFile(filepath.Join(home, ".ssh", "id_ed25519"))
}

// Dial connects to the server.
func Dial(addr string) (net.Conn, error) {
	key, _ := DefaultKey()
	_ = key
	return net.Dial("tcp", addr)
}
