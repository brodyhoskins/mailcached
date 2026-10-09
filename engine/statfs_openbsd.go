package engine

import "golang.org/x/sys/unix"

// statfs returns the bytes available to the proxy and the size of dir's
// file system.
func statfs(dir string) (avail, total uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return uint64(max(st.F_bavail, 0)) * uint64(st.F_bsize), st.F_blocks * uint64(st.F_bsize), nil
}
