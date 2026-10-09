// Command mailcached is a local IMAP and SMTP server for mail clients that
// sits in front of any mail provider. It keeps a local copy of each
// account's folders and flags and caches the messages clients read, so
// clients get answers at once.
//
//	mailcached -config /etc/mailcached/mailcached.yaml
package main

import (
	"os"

	"github.com/brodyhoskins/mailcached/config"
	"github.com/brodyhoskins/mailcached/daemon"
	"github.com/brodyhoskins/mailcached/internal/version"
)

func main() {
	os.Exit(daemon.Main(daemon.Program{
		Name:    version.Product,
		Version: version.String(),
		Files:   config.Mailcached(),
	}, os.Args[1:], os.Stdout, os.Stderr))
}
