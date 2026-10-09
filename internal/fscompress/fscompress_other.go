//go:build !linux

package fscompress

func compresses(string) (bool, string) { return false, "" }
