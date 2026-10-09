#!/bin/sh
set -e

for shell in /usr/sbin/nologin /sbin/nologin /bin/false; do
	[ -x "$shell" ] && break
done

if ! grep -q '^mailcached:' /etc/group; then
	if command -v groupadd >/dev/null 2>&1; then
		groupadd --system mailcached
	else
		addgroup -S mailcached
	fi
fi

if ! id mailcached >/dev/null 2>&1; then
	if command -v useradd >/dev/null 2>&1; then
		useradd --system --gid mailcached --home-dir /var/cache/mailcached --no-create-home --shell "$shell" mailcached
	else
		adduser -S -D -H -h /var/cache/mailcached -s "$shell" -G mailcached mailcached
	fi
fi
