# Troubleshooting

```bash
systemctl status flowcollector
journalctl -u flowcollector -n 100 --no-pager
flowcollector diagnostics --config /etc/flowcollector/config.yaml
flowcollector health --url http://127.0.0.1:8080/health
```

## Browser access in v1.2.0

Default URL:

```text
http://127.0.0.1:8080
```

Do **not** prepend `https://` unless you explicitly enabled HTTPS with a trusted certificate/key. In the default profile there is no SSL/TLS handshake and therefore no certificate warning to accept.

If you upgraded from v1.0.0 with its generated self-signed profile, the installer detects the legacy `tls: true` plus empty certificate paths, backs up the configuration, switches it to `tls: false`, and changes the legacy `8443` web port to `8080` when appropriate.

If `web.tls: true` is configured, the application refuses to start unless both explicit certificate files are configured and valid. This prevents falling back to an unexpected self-signed certificate.

If flows do not appear, first verify the exporter source has an ALLOW rule. DEFAULT DENY is intentional. Then check the listener port, exporter protocol/version, template status and decoder error counters.

## `users.json: permission denied` after systemd installation

This was a v1.0.1 migration defect when the collector had previously been run manually as root. Upgrade to v1.2.0 and rerun:

```bash
sudo ./install.sh
```

The installer repairs ownership under the configured collector data directory before restarting the unprivileged service. For an immediate repair of the default installation:

```bash
sudo systemctl stop flowcollector
sudo chown -R flowcollector:flowcollector /var/lib/flowcollector
sudo chmod 600 /var/lib/flowcollector/bootstrap-admin.txt 2>/dev/null || true
sudo systemctl restart flowcollector
/usr/local/bin/flowcollector health --url http://127.0.0.1:8080/health
```
