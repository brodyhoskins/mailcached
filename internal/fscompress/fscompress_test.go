package fscompress

import "testing"

const mountinfo = `22 1 179:2 / / rw,noatime - ext4 /dev/mmcblk0p2 rw
30 22 0:40 / /srv rw,noatime - btrfs /dev/sda1 rw,compress=zstd:3,space_cache=v2,subvol=/
31 22 0:41 / /srv/plain rw,noatime - btrfs /dev/sda2 rw,space_cache=v2
32 22 0:42 / /var/cache/my\040cache rw - ext4 /dev/zram1 rw
33 22 0:43 / /forced rw - btrfs /dev/sdb1 rw,compress-force=lzo
34 22 0:44 / /zfs rw - zfs tank/data rw,xattr
`

func TestCompresses(t *testing.T) {
	mounts := parseMountinfo(mountinfo)
	for _, c := range []struct {
		dir, prop string
		want      bool
		why       string
	}{
		{"/var/cache/mailcached", "", false, ""},
		{"/srv/cache", "", true, "btrfs compress=zstd:3"},
		{"/srv", "", true, "btrfs compress=zstd:3"},
		{"/srv/plain/cache", "", false, ""},
		{"/srv/plain/cache", "zstd", true, "btrfs property compression=zstd"},
		{"/srv/plainer", "", true, "btrfs compress=zstd:3"},
		{"/var/cache/my cache/x", "", true, "zram /dev/zram1"},
		{"/forced/x", "", true, "btrfs compress-force=lzo"},
		{"/zfs/x", "", false, ""},
	} {
		m, ok := mountFor(mounts, c.dir)
		if !ok {
			t.Fatalf("%s: no mount", c.dir)
		}
		if got, why := decide(m, c.prop); got != c.want || why != c.why {
			t.Errorf("%s (property %q) = %v %q, want %v %q", c.dir, c.prop, got, why, c.want, c.why)
		}
	}
}
