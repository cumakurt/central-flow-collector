# Protokol desteği

Kaynak: [PROTOCOLS.md](../PROTOCOLS.md)

Collector NetFlow v1/v5/v7/v8/v9, IPFIX (NetFlow v10) ve sFlow v5 kabul eder.
NetFlow v8 için Cisco uyumlu aggregation şemaları 1–14 normalleştirilir.
IPFIX; UDP yanında `transport: tcp` veya `transport: sctp` ile alınabilir.
SCTP soketi Linux derlemelerinde IPv4 bind ile kullanılabilir; TLS/DTLS dış
proxy veya load balancer tarafından sonlandırılmalıdır.

## Dinleyiciler ve şablonlar

`protocol: netflow` paket sürümünü otomatik seçer; varsayılan port 2055’tir.
`protocol: ipfix` varsayılan 4739, `protocol: sflow` varsayılan 6343’tür.
IPFIX TCP/SCTP bağlantıları IPFIX başlığındaki mesaj uzunluğuyla çerçevelenir.
Şablonlar gönderici, taşıma/kaynak portu, dinleyici, observation domain ve
template ID ile izole edilir. Enterprise IE’ler, değişken uzunluklu alanlar,
options kayıtları, reverse counters, NAT/VRF/firewall alanları ve bilinmeyen
özel alanların ham gösterimi desteklenir.

## Sınırlar

TLS/DTLS, sFlow v2/v4, structured/list IE’lerin özyinelemeli semantiği ve
donanım/firmware sertifikasyonu bu collector’ın kapsamı dışındadır. Bilinmeyen
enterprise alanları kaybolmaz; `custom` içinde hex olarak korunur.
