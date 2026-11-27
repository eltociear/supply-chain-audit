package zlib

/*
#cgo LDFLAGS: -lz
#cgo pkg-config: zlib
#include <zlib.h>
#include <stdlib.h>
static const char* ver(void) { return zlibVersion(); }
*/
import "C"

// Version returns the zlib version.
func Version() string { return C.GoString(C.ver()) }
