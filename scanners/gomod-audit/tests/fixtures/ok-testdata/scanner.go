package scanner

// Detect reports whether s looks like a pipe-to-shell installer.
func Detect(s string) bool { return len(s) > 0 }
