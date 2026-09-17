# RPM packaging

The checked-in spec supports x86_64 and aarch64 release binaries. On an RPM build host with `rpmbuild` installed, run:

```bash
VERSION=4.0.0 ARCH=amd64 ./scripts/build-rpm.sh
VERSION=4.0.0 ARCH=arm64 ./scripts/build-rpm.sh
```

The script copies the matching prebuilt collector binary, configuration and hardened systemd unit into an isolated rpmbuild tree and places the resulting RPM in `dist/`.
