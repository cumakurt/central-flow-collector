# Yapılandırma

Kaynak: [CONFIGURATION.md](../CONFIGURATION.md)

Kanonik örnek [`config.example.yaml`](../../config.example.yaml) dosyasıdır.
Değişiklikten sonra `flowcollector config validate --config FILE` çalıştırın.
Dinleyicide `protocol: ipfix` ile `transport: udp`, `tcp` veya Linux üzerinde
`sctp` seçilebilir. TCP/SCTP yalnızca IPFIX için geçerlidir; NetFlow ve sFlow
taşımaları UDP’dir. Varsayılan portlar sırasıyla 2055, 4739 ve 6343’tür.

Gizli değerleri `@env:NAME` veya `@file:/path` ile yükleyin. `storage.data_dir`,
bootstrap dosyası ve baseline dosyası kurulum betikleri tarafından hedef OS’ye
uygun yazılabilir dizinlere ayarlanır.
