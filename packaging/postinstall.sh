#!/bin/sh
set -e

[ -d /etc/mailcached ] || install -d -m 0750 -o root -g mailcached /etc/mailcached
[ -d /var/cache/mailcached ] || install -d -m 0700 -o mailcached -g mailcached /var/cache/mailcached
