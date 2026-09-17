# Sorun giderme

Kaynak: [TROUBLESHOOTING.md](../TROUBLESHOOTING.md)

Akış görünmüyorsa protokol, taşıma, port, güvenlik duvarı, gönderici politikası,
listener sayaçları, decoder hataları, kuyruk drop’ları ve depolama sağlığını
kontrol edin. IPFIX stream için `protocol: ipfix` ve `transport: tcp` veya
`transport: sctp` kullanılmalıdır; SCTP yalnızca Linux build’de çalışır.
Önce `config validate`, sonra listener/health uçlarını çalıştırın. UDP gönderim
başarısı collector kabulünü garanti etmez.
