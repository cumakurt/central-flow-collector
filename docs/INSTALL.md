# Installation

## Binary / systemd

Choose the correct `dist/flowcollector-linux-*` binary, then either run `sudo ./install.sh` or install the corresponding `.deb` package. The installer creates the service account, `/etc/flowcollector`, `/var/lib/flowcollector` and a hardened systemd unit. Validate configuration before starting.

## Container

Use `deploy/docker/` for Docker/Podman-compatible builds or `deploy/helm/central-flow-collector` for Kubernetes.

For high-rate UDP collection increase host receive buffers and verify NIC/kernel drops. Production ClickHouse should be sized and backed up independently of the collector package.
