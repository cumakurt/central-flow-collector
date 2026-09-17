# Installation

## Binary / systemd

Choose the correct `dist/flowcollector-linux-*` binary, then either run `sudo ./install.sh` or install the corresponding `.deb` package. The installer creates the service account, `/etc/flowcollector`, `/var/lib/flowcollector` and a hardened systemd unit. Validate configuration before starting.

## Container

Use `deploy/docker/` for Docker/Podman-compatible builds or `deploy/helm/central-flow-collector` for Kubernetes.

For high-rate UDP collection increase host receive buffers and verify NIC/kernel drops. Production ClickHouse should be sized and backed up independently of the collector package.

## Windows

Use an elevated PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1 -Version 4.0.0
```

The script installs `flowcollector.exe`, creates a validated configuration,
and registers the `CentralFlowCollector` service. `-NoService -NoStart` leaves
the binary for a foreground deployment. `uninstall.ps1` removes the service
and binaries; data is retained unless `-PurgeData` is specified.

## macOS and BSD

`install-portable.sh` detects Darwin/FreeBSD/OpenBSD/NetBSD and the host
architecture. It uses a matching `dist/` artifact when available and otherwise
builds with `CGO_ENABLED=0` and the local Go toolchain. macOS receives a
launchd plist; FreeBSD is installed as a portable binary with an rc.d note.
Linux installations with systemd should continue to use `install.sh`.
