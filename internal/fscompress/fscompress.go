// Package fscompress tells whether a directory is on a file system that
// compresses what is written to it, so the cache need not compress too.
//
// It recognizes Btrfs mounted with compress or compress-force, a Btrfs
// directory with the compression property (btrfs property set DIR
// compression zstd), and a file system on a zram device. ZFS keeps its
// compression setting out of the mount table, so it is not recognized.
// Other systems than Linux are never recognized.
package fscompress

import (
	"path/filepath"
	"strings"
)

// Compresses reports whether dir's file system compresses new files, and
// why (for example "btrfs compress=zstd:3"). An error reading the mount
// table counts as no.
func Compresses(dir string) (bool, string) {
	return compresses(dir)
}

// mount is one line of /proc/self/mountinfo.
type mount struct {
	point, fstype, source, options string
}

// parseMountinfo reads the lines of /proc/self/mountinfo (proc(5)):
// "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue".
func parseMountinfo(s string) []mount {
	var out []mount
	for line := range strings.Lines(s) {
		left, right, ok := strings.Cut(strings.TrimSpace(line), " - ")
		if !ok {
			continue
		}
		l, r := strings.Fields(left), strings.Fields(right)
		if len(l) < 5 || len(r) < 2 {
			continue
		}
		m := mount{point: unescape(l[4]), fstype: r[0], source: r[1]}
		if len(r) > 2 {
			m.options = r[2]
		}
		out = append(out, m)
	}
	return out
}

// unescape undoes the octal escapes of the mount table (\040 for a space).
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, ok := octal(s[i+1 : i+4]); ok {
				b.WriteByte(n)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func octal(s string) (byte, bool) {
	if len(s) != 3 {
		return 0, false
	}
	var n int
	for _, c := range s {
		if c < '0' || c > '7' {
			return 0, false
		}
		n = n*8 + int(c-'0')
	}
	return byte(n), n < 256
}

// mountFor returns the mount that holds path: the last one, in mount
// order, whose mount point is path or a parent of it.
func mountFor(mounts []mount, path string) (mount, bool) {
	var best mount
	found := false
	for _, m := range mounts {
		if m.point == path || m.point == "/" || strings.HasPrefix(path, strings.TrimSuffix(m.point, "/")+"/") {
			if !found || len(m.point) >= len(best.point) {
				best, found = m, true
			}
		}
	}
	return best, found
}

// decide applies the rules to the mount of dir. prop is the directory's
// btrfs.compression property, "" if none.
func decide(m mount, prop string) (bool, string) {
	if strings.HasPrefix(m.source, "/dev/zram") {
		return true, "zram " + m.source
	}
	if m.fstype != "btrfs" {
		return false, ""
	}
	if prop != "" && prop != "none" && prop != "no" {
		return true, "btrfs property compression=" + prop
	}
	for _, o := range strings.Split(m.options, ",") {
		name, value, _ := strings.Cut(o, "=")
		if (name == "compress" || name == "compress-force") && value != "no" {
			return true, "btrfs " + o
		}
	}
	return false, ""
}

func clean(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	return dir
}
