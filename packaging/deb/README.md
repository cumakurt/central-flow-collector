# Debian packaging

Run `VERSION=4.0.0 ./scripts/build-deb.sh` after `make package` or after the Linux amd64/arm64 collector binaries have been built. The package installs the collector to `/usr/local/bin/flowcollector`, the configuration to `/etc/flowcollector/config.yaml`, and a hardened systemd unit. The configuration is marked as a Debian conffile so upgrades preserve administrator changes.
