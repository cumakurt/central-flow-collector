# Kurulum

Kaynak: [INSTALL.md](../INSTALL.md)

## Linux

systemd kullanan Linux sunucularında `sudo ./install.sh` veya uygun DEB/RPM
paketini kullanın. Betik servis hesabı, yapılandırma, veri dizini ve sertleş-
tirilmiş servis birimini oluşturur. Yeniden başlatmadan önce:

```sh
sudo /usr/local/bin/flowcollector config validate --config /etc/flowcollector/config.yaml
```

## Windows

Yönetici PowerShell açın:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1 -Version 4.0.0
```

`CentralFlowCollector` servisi oluşturulur. `-NoService -NoStart` ön plan
kurulumu, `uninstall.ps1 -PurgeData` ise veriler dahil kaldırmayı sağlar.

## macOS ve BSD

systemd olmayan sistemlerde `install-portable.sh` işletim sistemi ve mimariyi
seçer; `dist/` ikilisini kullanır veya `CGO_ENABLED=0` ile Go kaynak kodunu
derler. macOS için launchd tanımı, FreeBSD için rc.d yönergesi sağlanır.

```sh
./install-portable.sh --prefix "$HOME/.local" --config-dir "$HOME/.config/flowcollector" --data-dir "$HOME/.local/share/flowcollector" --no-service
```
