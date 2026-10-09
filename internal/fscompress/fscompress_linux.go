package fscompress

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func compresses(dir string) (bool, string) {
	dir = clean(dir)
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, ""
	}
	m, ok := mountFor(parseMountinfo(string(b)), dir)
	if !ok {
		return false, ""
	}
	var prop string
	if m.fstype == "btrfs" {
		buf := make([]byte, 64)
		if n, err := unix.Getxattr(dir, "btrfs.compression", buf); err == nil {
			prop = strings.TrimRight(string(buf[:n]), "\x00")
		}
	}
	return decide(m, prop)
}
