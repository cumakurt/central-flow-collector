# API

Kaynak: [API.md](../API.md) · Şema: [openapi.yaml](../openapi.yaml)

API, tek organizasyonlu RBAC modeliyle çalışır. `administrator`, `analyst` ve
`read_only` rollerine göre portal, rapor, politika, sağlık ve analiz uçları
korunur. Akış filtreleri `src_ip`, `dst_ip`, CIDR, port, `ip_protocol`, app,
exporter, ASN, ülke, site, TCP flags, byte/packet ve süre alanlarını destekler.

OpenAPI dosyası makine tarafından tüketilen kanonik sözleşmedir; bu Türkçe
belge uç noktaların anlamını açıklar ve JSON alan adlarını çevirmeden korur.
