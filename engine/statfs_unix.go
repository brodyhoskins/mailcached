//go:build unix && !netbsd && !openbsd

package engine

import "golang.org/x/sys/unix"

// statfs returns the bytes available to the proxy and the size of dir's
// file system.
func statfs(dir string) (avail, total uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), uint64(st.Blocks) * uint64(st.Bsize), nil
}
