# Güvenlik

Kaynak: [SECURITY.md](../SECURITY.md)

Gönderici allow/deny politikaları ve paket hız sınırları UDP ile IPFIX TCP/SCTP
ingestion yüzeylerini korur. TLS/DTLS dış proxy’de sonlandırılmalı; collector
üzerinde varsayılan web bind loopback’tir. Gizli bilgiler YAML içine düz metin
olarak yazılmamalı, environment veya dosya referansları kullanılmalıdır.
RBAC, MFA/passkey, OIDC, LDAP, API token kapsamları, audit zinciri ve backup
bütünlüğü üretim kontrollerinin parçasıdır.
