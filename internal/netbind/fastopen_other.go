//go:build !linux

package netbind

// fastOpen does nothing here: Go reaches TCP Fast Open with socket
// options on Linux only.
func fastOpen(int) {}

// FastOpenHint returns "": there is nothing to set.
func FastOpenHint() string { return "" }
