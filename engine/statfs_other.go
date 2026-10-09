//go:build !unix

package engine

func statfs(string) (avail, total uint64, err error) { return 0, 0, errNoStatfs }
