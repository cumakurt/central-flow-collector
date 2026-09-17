# MASTER PROMPT — CENTRAL FLOW COLLECTOR

## Rolün

Bu görevde kıdemli bir **Software Architect, Network Telemetry Engineer, Flow Analytics Engineer, Backend Performance Engineer, Database Architect ve Enterprise UI/UX Designer** olarak hareket et.

Mevcut Merkezi Flow Toplayıcı uygulamasını yalnızca yüzeysel olarak geliştirme. Uygulamanın mevcut kaynak kodunu, veri modelini, ingestion pipeline'ını, depolama mimarisini, sorgulama yapısını, frontend bileşenlerini ve kullanıcı deneyimini bütünsel olarak analiz et.

Bu geliştirme turunun ana odağı:

- kod kalitesi,
- mimari sadelik,
- uygulama mantığı,
- performans,
- ölçeklenebilirlik,
- sorgulama ve analiz yetenekleri,
- görsel kalite,
- dashboard tasarımı,
- raporlama,
- kullanılabilirlik,
- ürünün gerçek kullanım amacına odaklanmasıdır.

Bu ürünün ne olduğunu ve ne olmadığını her teknik kararda göz önünde bulundur.

---

# 1. ÜRÜNÜN ANA AMACI

Bu ürün bir:

**High-performance Central Flow Collector & Flow Analytics Platform**

olmalıdır.

Temel amacı çok yüksek miktardaki network flow verisini merkezi olarak:

- toplamak,
- normalize etmek,
- indekslemek,
- saklamak,
- sorgulamak,
- filtrelemek,
- korelasyon yapmak,
- analiz etmek,
- görselleştirmek,
- raporlamak

olmalıdır.

Desteklenen veya mimari olarak desteklenmesi gereken başlıca veri kaynakları arasında mümkün olduğu ölçüde:

- NetFlow v5
- NetFlow v9
- IPFIX
- sFlow

yer almalıdır.

Mevcut uygulamada bunlardan bazıları eksikse mimariyi değerlendir ve uygulanabilir olanları ürün kapsamına uygun şekilde ekle.

---

# 2. ÜRÜNÜN NE OLMADIĞI

Bu ürün:

- NDR değildir.
- SIEM değildir.
- SOAR değildir.
- EDR değildir.
- IDS/IPS değildir.
- packet capture ürünü değildir.
- malware analiz sistemi değildir.
- multi-tenant SaaS platformu değildir.

Ürünü gereksiz biçimde bu alanlara sürükleme.

Örneğin:

- malware tespiti,
- davranışsal tehdit analizi,
- ML tabanlı saldırı tespiti,
- reverse shell detection,
- IDS signature engine,
- endpoint monitoring,
- vulnerability scanner

gibi flow collector'ın ana görevinden uzaklaştıran özellikler mevcutsa bunları değerlendir.

Ürüne değer katmayan, odağı bozan veya gereksiz karmaşıklık yaratan özellikleri kaldır.

Flow verisinden doğal olarak çıkarılabilecek network görünürlüğü ve istatistiksel anomaliler ürün kapsamında kalabilir; ancak ürünü bir NDR platformuna dönüştürme.

---

# 3. MULTI-TENANT OLMAYACAK

Bu uygulama multi-tenant olmayacak.

Bir kurum veya tek organizasyon kendi altyapısındaki tüm flow verilerini merkezi olarak bu sisteme gönderecek.

Bu nedenle:

- tenant management,
- tenant isolation,
- tenant billing,
- tenant bazlı quota,
- tenant bazlı RBAC,
- tenant onboarding

gibi gereksiz mimari katmanlar kullanılmamalıdır.

Kurumsal kullanıcı ve rol yönetimi gerekiyorsa basit ve anlaşılır RBAC uygulanabilir.

Örneğin:

- Administrator
- Analyst
- Read Only

gibi roller yeterlidir.

---

# 4. ÖNCE MEVCUT UYGULAMAYI DERİNLEMESİNE ANALİZ ET

Kod değiştirmeye başlamadan önce mevcut uygulamayı sistematik biçimde incele.

Aşağıdaki konuları analiz et:

### Backend

- kod organizasyonu,
- package/modül yapısı,
- dependency yönetimi,
- concurrency modeli,
- goroutine/thread kullanımı,
- locking,
- channel kullanımı,
- batching,
- queue yönetimi,
- error handling,
- logging,
- configuration management,
- resource lifecycle,
- graceful shutdown,
- memory allocation,
- connection pooling,
- query execution,
- API tasarımı,
- background workers,
- retry politikaları.

### Flow ingestion

İncele:

Flow Packet
→ Listener
→ Decoder
→ Validation
→ Normalization
→ Enrichment
→ Aggregation
→ Batch
→ Storage

Bu zincirde:

- gereksiz kopyalama,
- serialization maliyeti,
- lock contention,
- GC pressure,
- gereksiz allocation,
- blocking operasyon,
- disk bottleneck,
- database bottleneck,
- queue saturation

olup olmadığını araştır.

### Database

İncele:

- mevcut schema,
- index kullanımı,
- partitioning,
- retention,
- compression,
- aggregate tablolar,
- time-series yaklaşımı,
- query planları,
- cardinality problemleri,
- yüksek hacimli sorgular,
- pagination,
- historical query performansı.

### Frontend

İncele:

- component mimarisi,
- state management,
- gereksiz re-render,
- büyük veri tabloları,
- grafik rendering maliyeti,
- WebSocket/SSE kullanımı,
- polling,
- API çağrı sayısı,
- caching,
- responsive design,
- navigation,
- information density.

---

# 5. BENZER ÜRÜNLERİ REFERANS AL

Açık kaynak ve ticari Central Flow Collector / Flow Analytics ürünlerinin genel yaklaşımını incele.

Özellikle aşağıdaki ürün kategorilerini referans al:

- ntopng
- Akvorado
- goflow2
- pmacct
- ElastiFlow
- SolarWinds NetFlow Traffic Analyzer
- ManageEngine NetFlow Analyzer
- Kentik
- Plixer Scrutinizer
- Grafana tabanlı flow analytics çözümleri

Amaç bu ürünleri kopyalamak değildir.

Şunları araştır:

- hangi dashboard'lar başarılı,
- hangi filtreleme yöntemleri kullanılıyor,
- hangi flow analizleri gerçekten kullanışlı,
- hangi grafikler karar vermeyi kolaylaştırıyor,
- CISO/Network Operations ekranları nasıl tasarlanıyor,
- hangi Top-N analizleri yaygın,
- hangi raporlar gerçek hayatta faydalı,
- yüksek hacimde nasıl sorgulama yapılıyor,
- uzun dönemli trend analizi nasıl sunuluyor.

Bu ürünlerde bulunan ve bizim ürünümüzün ana görevini güçlendiren özellikleri uygun olduğu ölçüde mevcut ürüne adapte et.

---

# 6. UI'DA GEREKSİZ ÖZELLİKLERİ KALDIR

Mevcut arayüzü baştan sona incele.

Her ekran için şu soruyu sor:

> "Bu ekran veya özellik, büyük miktarda flow datasını anlamaya, sorgulamaya, analiz etmeye veya raporlamaya gerçekten yardımcı oluyor mu?"

Cevap hayır ise:

- kaldır,
- sadeleştir,
- başka ekranla birleştir
  veya
- daha faydalı bir özellik ile değiştir.

Arayüz özellik dolu görünmek için özellik barındırmamalıdır.

Amaç:

**daha az ama çok daha güçlü ekranlar oluşturmak.**

---

# 7. ANA DASHBOARD

Ana dashboard profesyonel bir network telemetry platformu gibi görünmelidir.

Dashboard yalnızca rakamların yer aldığı kartlardan oluşmamalıdır.

Kullanıcı sisteme girdiğinde network trafiğinin genel durumunu birkaç saniye içinde anlayabilmelidir.

Dashboard'ta uygun olduğu ölçüde aşağıdaki bilgiler bulunmalıdır:

### Genel KPI

- Total Flows
- Flows/sec
- Traffic/sec
- Total Bytes
- Total Packets
- Unique Source IP
- Unique Destination IP
- Unique Conversations
- Unique Autonomous Systems
- Unique Countries
- Active Exporters
- Active Interfaces
- TCP / UDP / ICMP dağılımı

### Top analizler

- Top Talkers
- Top Source IP
- Top Destination IP
- Top Conversations
- Top Applications
- Top Protocols
- Top Source Ports
- Top Destination Ports
- Top Autonomous Systems
- Top Countries
- Top Exporters
- Top Interfaces

### Trafik yönleri

Mümkünse:

- inbound,
- outbound,
- internal,
- external,
- transit

trafikleri açık biçimde ayrıştır.

---

# 8. CISO / EXECUTIVE OVERVIEW

Ayrı bir üst düzey yönetim görünümü oluştur.

Bu ekran teknik ayrıntıyı azaltmalı fakat network kullanımının genel görünümünü çok iyi göstermelidir.

Örnek bilgiler:

- toplam trafik hacmi,
- önceki dönem karşılaştırması,
- bandwidth trendleri,
- en yoğun kaynaklar,
- en yoğun lokasyonlar,
- en yoğun application/protocol kategorileri,
- internet / internal trafik oranları,
- top countries,
- top ASNs,
- trafik büyüme trendleri,
- kapasite kullanım eğilimleri.

Örneğin:

Last 24 Hours

Traffic:
2.4 TB

Change:
+18.3%

Peak:
4.7 Gbps

Peak Time:
14:32

şeklinde okunabilir özetler oluştur.

---

# 9. FLOW EXPLORER

Ürünün en güçlü ekranlarından biri gelişmiş **Flow Explorer** olmalıdır.

Kullanıcı çok büyük flow datasında hızlı sorgulama yapabilmelidir.

Örnek filtreler:

- src\_ip
- dst\_ip
- src\_port
- dst\_port
- protocol
- bytes
- packets
- exporter
- interface
- ASN
- country
- application
- direction
- subnet
- TCP flags
- time
- flow duration

Filtreler kombine edilebilmelidir.

Örneğin:

src\_ip = 10.10.5.25
AND
dst\_port = 443
AND
bytes > 10MB
AND
country != TR

gibi sorgular desteklenebilir.

Arayüzde kullanıcının karmaşık query syntax öğrenmesini zorunlu tutma.

Visual Query Builder oluştur.

---

# 10. TIME RANGE ANALYSIS

Uygulamanın her önemli analiz ekranında zaman seçimi bulunmalıdır.

Örnek:

- Last 5 Minutes
- Last 15 Minutes
- Last 30 Minutes
- Last 1 Hour
- Last 6 Hours
- Last 12 Hours
- Last 24 Hours
- Last 7 Days
- Last 30 Days
- Custom Range

Seçilen zaman aralığı bütün ilgili dashboard bileşenlerini senkronize olarak etkilemelidir.

Örneğin kullanıcı:

01.09.2026 08:00
ile
05.09.2026 18:00

arasını seçtiğinde tüm grafikler, Top-N tabloları ve analizler bu zaman aralığına göre yeniden hesaplanmalıdır.

---

# 11. DÖNEM KARŞILAŞTIRMA

Mümkünse çok güçlü bir "Compare Period" özelliği oluştur.

Örneğin:

Last 24 Hours

vs

Previous 24 Hours

veya

This Week

vs

Previous Week

Analizlerde değişim yüzdeleri göster.

Örneğin:

Total Traffic
+24.8%

Unique Destinations
+7.2%

UDP Traffic
-18.5%

External Traffic
+31.1%

---

# 12. GRAFİKLER

Görsel analiz bu ürünün en önemli parçalarından biridir.

Ancak grafik eklemek için grafik ekleme.

Her grafik belirli bir soruya cevap vermelidir.

Kullanılabilecek grafikler:

- Time Series
- Area Chart
- Stacked Area
- Bar Chart
- Horizontal Bar
- Pie / Donut
- Heatmap
- Sankey
- Treemap
- Geo Map
- Histogram

Her grafik için uygun görselleştirme tipini seç.

Örneğin flow yönleri için Sankey:

Source Networks
→
Applications
→
Destination Networks

gibi oldukça faydalı olabilir.

---

# 13. NETWORK TRAFFIC MATRIX

Source ve Destination subnet/network arasındaki trafik yoğunluğunu gösteren bir Matrix/Heatmap oluşturmayı değerlendir.

Örneğin:

```
          Destination

```

Source DC Users WAN Internet

DC 2GB 800MB 5GB 12GB
Users 1GB 100MB 2GB 70GB
WAN 4GB 2GB 1GB 10GB

Bu ekran büyük ağlarda network davranışının hızlı anlaşılmasını sağlar.

---

# 14. ASN ANALYSIS

Flow verilerinden ASN bilgisi çıkarılabiliyorsa ayrı ASN analizi oluştur.

Göster:

- Top ASNs
- Traffic by ASN
- Connections by ASN
- Source ASN
- Destination ASN
- ASN → ASN traffic
- ASN trends

---

# 15. GEO ANALYSIS

GeoIP enrichment mevcutsa veya güvenli ve performanslı şekilde eklenebiliyorsa:

- Traffic by Country
- Source Countries
- Destination Countries
- Country → Country traffic
- World Map
- Top Countries

oluştur.

Geo analizini threat intelligence ürünü gibi tasarlama.

Amaç trafik görünürlüğüdür.

---

# 16. APPLICATION / PROTOCOL ANALYSIS

Flow verisinden veya mevcut metadata'dan güvenilir biçimde belirlenebildiği ölçüde:

- Applications
- Protocols
- Ports
- Service categories

analiz edilebilsin.

Örnek dashboard:

Application Traffic

HTTPS 38%
DNS 14%
QUIC 11%
SSH 5%
SMTP 4%
Other 28%

---

# 17. EXPORTER HEALTH

Flow exporter kaynaklarının sağlık durumunu gösteren ayrı ekran oluştur.

Gösterilebilecek bilgiler:

- exporter IP,
- exporter name,
- flow type,
- last seen,
- flow rate,
- sampling rate,
- dropped flows,
- interface count,
- uptime,
- sequence problems,
- packet loss,
- parsing errors.

Bir exporter veri göndermeyi durdurduğunda arayüzde açık şekilde görülebilmelidir.

---

# 18. DATA INGESTION HEALTH

Sistemin kendi ingestion durumunu izlemek için ekran oluştur.

Örneğin:

Received:
1.4M flows/sec

Decoded:
1.39M flows/sec

Dropped:
0.01%

Queue:
18%

Storage Write:
820k rows/sec

Query Latency:
P95 210ms

Bu ekran ürünün kendi kapasitesini anlamak için kullanılmalıdır.

---

# 19. RAPORLAMA

Profesyonel bir Reporting modülü oluştur.

Kullanıcı bir zaman aralığı seçip rapor oluşturabilmelidir.

Örneğin:

Network Usage Report
Top Talkers Report
Top Applications Report
Top Destinations Report
Bandwidth Report
ASN Report
Country Report
Exporter Report
Interface Report
Executive Summary

Raporlar:

- PDF
- XLSX / Excel
- CSV
- JSON

formatlarında export edilebilmelidir.

Uygun ve faydalı olması halinde:

- PNG / SVG chart export

da eklenebilir.

---

# 20. PDF RAPOR KALİTESİ

PDF export basit bir browser screenshot olmamalıdır.

Kurumsal görünümlü rapor üret.

Örneğin:

Company / Product Name

Network Flow Analysis Report

Period:
01 Sep 2026 – 07 Sep 2026

Executive Summary

Traffic Overview

Top Talkers

Top Applications

Top Destinations

ASN Distribution

Geo Distribution

Traffic Trends

Exporter Health

Raporda:

- düzgün sayfa düzeni,
- grafikler,
- tablolar,
- tarih aralığı,
- oluşturulma zamanı,
- toplamlar,
- karşılaştırmalar

bulunmalıdır.

---

# 21. EXCEL EXPORT

Excel export yalnızca ekrandaki birkaç satırı dışa aktarmamalıdır.

Mümkünse gerçek analiz sonucunu export et.

Workbook sheet'leri örneğin:

Overview
Top Talkers
Top Sources
Top Destinations
Applications
Protocols
ASNs
Countries
Exporters
Interfaces
Raw Results

şeklinde ayrılabilir.

---

# 22. SAVED VIEWS

Kullanıcı sık yaptığı sorguları kaydedebilsin.

Örneğin:

Internet Traffic
DNS Traffic
Data Center Traffic
Backup Traffic
Top External Destinations

Saved View aşağıdakileri saklayabilir:

- filters,
- columns,
- sort,
- grouping,
- visualization,
- time configuration.

---

# 23. DRILL-DOWN

Grafikler statik olmamalı.

Kullanıcı bir grafik öğesine tıkladığında ilgili flow'lara drill-down yapabilmelidir.

Örneğin:

Top Country → Germany

tıklandığında:

country = DE

filtresi otomatik oluşmalı.

Ardından kullanıcı:

Top Applications
Top Sources
Top Destinations

analizlerini görebilmelidir.

---

# 24. PERFORMANS ANA ÖNCELİKTİR

Bu ürün çok büyük flow datasıyla çalışmak üzere tasarlanmalıdır.

Hedef:

- yüz milyonlarca flow,
- milyarlarca flow kaydı,
- yüksek ingestion rate,
- uzun süreli retention

gibi senaryolardır.

Kod ve mimariyi bu ölçeği dikkate alarak değerlendir.

Özellikle:

- zero/low allocation parsing,
- object pooling gerektiğinde,
- batching,
- bulk insert,
- asynchronous writes,
- backpressure,
- bounded queues,
- efficient encoding,
- memory reuse,
- cache efficiency,
- partition pruning,
- materialized aggregates,
- pre-aggregation,
- query caching,
- cardinality control

gibi teknikleri değerlendir.

Ancak gereksiz complexity oluşturma.

---

# 25. UI BÜYÜK DATASET İLE ÇALIŞMALI

Frontend hiçbir zaman milyonlarca satırı doğrudan browser'a yüklememelidir.

Kullan:

- server-side filtering,
- server-side sorting,
- pagination,
- cursor pagination,
- virtualized tables,
- aggregation API.

Tablolarda mümkünse:

- column selection,
- resize,
- sort,
- filter,
- grouping,
- pinning,
- export

özellikleri bulunmalıdır.

---

# 26. SORGU PERFORMANSI

Dashboard açıldığında onlarca pahalı query çalıştırma.

Mümkün olduğunca:

- ortak sorguları birleştir,
- aggregate endpoint kullan,
- cache kullan,
- time bucket kullan,
- pre-aggregation kullan.

Ama cache invalidation mantığını doğru tasarla.

---

# 27. REAL-TIME MODU

Gerçek zamanlı ekranlar varsa gereksiz yere her saniye bütün dashboard'u yenileme.

Akıllı update mekanizması kullan.

Örneğin:

WebSocket
veya
Server-Sent Events

uygunsa değerlendir.

UI yalnızca değişen dataset'i güncellesin.

---

# 28. TIME-SERIES AGGREGATION

Uzun zaman aralıklarında raw flow'ları sürekli taramak yerine gerektiğinde aggregation stratejisi kullan.

Örneğin:

1 minute
5 minute
15 minute
1 hour
1 day

roll-up tabloları.

Örneğin:

7 günlük grafik için saniyelik verileri sorgulamak yerine 15 dakikalık aggregate kullanılabilir.

---

# 29. DATA RETENTION

Retention yönetimi tasarla.

Örneğin:

Raw Flow:
30 days

5 Minute Aggregates:
90 days

Hourly Aggregates:
1 year

Daily Aggregates:
Unlimited

Bu değerler configurable olmalıdır.

Ancak varsayılan değerleri mevcut ürün mimarisi ve storage maliyetine göre mantıklı belirle.

---

# 30. STORAGE KAPASİTE GÖRÜNÜMÜ

UI'da storage durumunu göster.

Örneğin:

Flow Storage:
2.4 TB

Retention:
30 days

Daily Growth:
82 GB/day

Estimated Remaining Capacity:
47 days

Bu bilgiler operasyon ekipleri için çok faydalıdır.

---

# 31. UI / UX TASARIM PRENSİPLERİ

Arayüz:

- modern,
- ciddi,
- kurumsal,
- teknik,
- sade,
- yüksek bilgi yoğunluklu,
- hızlı okunabilir

olmalıdır.

Bir "startup landing page" gibi görünmemelidir.

Aynı zamanda eski network appliance arayüzleri gibi de görünmemelidir.

Modern enterprise observability ürünlerine yaklaş.

Referans alınabilecek tasarım yaklaşımı:

Grafana
Datadog
Cloudflare
Elastic
Kentik

Ama birebir kopyalama yapma.

---

# 32. DARK MODE

Profesyonel Dark Mode destekle.

Grafik renklerinde:

- yeterli contrast,
- kolay ayrışma,
- color-blind friendly palette

kullan.

Renk kullanımını abartma.

---

# 33. INFORMATION DENSITY

Network analyst ekranları yüksek bilgi yoğunluğu gerektirir.

Gereğinden büyük:

- kartlar,
- boşluklar,
- başlıklar,
- ikonlar

kullanma.

Ekran alanını verimli kullan.

---

# 34. SEARCH

Global Search eklemeyi değerlendir.

Örneğin kullanıcı:

8.8.8.8

yazdığında hızlı şekilde:

IP Overview

Traffic:
32 GB

Flows:
1.2M

Top Ports:
443
53

Top Sources:
...

Top Exporters:
...

Timeline:
...

gibi analiz görebilsin.

---

# 35. IP DETAIL PAGE

Bir IP seçildiğinde detay ekranı açılabilir.

Göster:

- total traffic,
- sent,
- received,
- flows,
- peers,
- ports,
- protocols,
- applications,
- ASN,
- country,
- timeline,
- exporters,
- interfaces,
- top destinations,
- top sources.

Bu bir threat investigation ekranı değil, flow analytics ekranıdır.

---

# 36. SUBNET ANALYSIS

CIDR/Subnet bazlı analiz destekle.

Örneğin:

10.10.0.0/16

için:

- traffic,
- top hosts,
- destinations,
- applications,
- protocols,
- external communication,
- timeline

göster.

---

# 37. INTERFACE ANALYSIS

Network cihazlarındaki interface bazlı flow bilgileri mevcutsa:

- ingress interface,
- egress interface,
- utilization,
- traffic,
- top protocols,
- top sources,
- top destinations

analiz edilebilsin.

---

# 38. ANALYTICS SAYFASI

Flow Analytics ürünün merkezinde olmalıdır.

Bu sayfada kullanıcı:

Dimension:

Source IP

Metric:

Bytes

Group By:

Country

Filter:

Protocol = TCP

Time:

Last 24 hours

şeklinde parametrik analiz oluşturabilsin.

Desteklenebilecek ölçüler:

- Bytes
- Packets
- Flows
- Sessions
- Unique Sources
- Unique Destinations
- Average Flow Size
- Average Duration
- Bits/sec
- Packets/sec
- Flows/sec

Desteklenebilecek dimension'lar:

- Source IP
- Destination IP
- Source Network
- Destination Network
- Protocol
- Source Port
- Destination Port
- Application
- Country
- ASN
- Exporter
- Interface
- Direction

---

# 39. ANALYSIS FIRST

Bu geliştirme turunda özellikle **analiz altyapısı** çok önemlidir.

Mevcut flow verisinden matematiksel ve istatistiksel olarak çıkarılabilecek faydalı tüm network analytics yeteneklerini değerlendir.

Ancak yalnızca gerçekten anlamlı olanları uygula.

Hedef:

Raw Flow Data

↓

Useful Network Intelligence

dönüşümüdür.

---

# 40. ANOMALİLER KONUSUNDA SINIR

Flow istatistiklerinden doğal olarak görülebilen:

- trafik sıçramaları,
- hacim değişiklikleri,
- yeni yoğun destination,
- sıra dışı protocol dağılımı,
- exporter veri kaybı

gibi operasyonel anomaliler gösterilebilir.

Ancak bunu:

AI Threat Detection

veya

NDR Detection Engine

gibi konumlandırma.

Örneğin:

Traffic Baseline Deviation

uygun olabilir.

"Possible C2 Detected"

bu ürün için uygun değildir.

---

# 41. KOD KALİTESİ

Kod genelinde:

- dead code,
- duplicate code,
- unused API,
- unused component,
- debug code,
- temporary hack,
- TODO bırakılmış kritik alan,
- gereksiz abstraction

tespit et ve temizle.

Fonksiyon ve package sınırlarını iyileştir.

Kod:

- okunabilir,
- maintainable,
- test edilebilir,
- predictable

olmalıdır.

---

# 42. GEREKSİZ OVERENGINEERING YAPMA

Her problem için yeni framework veya dependency ekleme.

Önce mevcut stack'i değerlendir.

Yeni dependency yalnızca açık teknik faydası varsa eklenmelidir.

---

# 43. SECURITY

Bu geliştirme turu güvenlik ürünü geliştirme turu değildir ancak uygulamanın kendisi güvenli olmalıdır.

Kontrol et:

- authentication,
- authorization,
- API validation,
- SQL injection,
- XSS,
- CSRF,
- secrets,
- configuration exposure,
- log leakage,
- unsafe file export,
- path traversal,
- SSRF,
- WebSocket auth,
- rate limiting,
- dependency vulnerabilities.

Bulduğun güvenlik açıklarını düzelt.

---

# 44. TESTLER

Yaptığın değişikliklerin tamamını test et.

Gerekli yerlerde:

- unit tests,
- integration tests,
- API tests,
- database tests,
- parser tests,
- frontend component tests,
- E2E tests

ekle.

Mevcut testleri de çalıştır.

---

# 45. LOAD TEST

Flow collector için synthetic load test oluştur veya mevcut olanı iyileştir.

Ölç:

- flows/sec,
- packets/sec,
- MB/sec,
- CPU,
- memory,
- allocation,
- dropped flows,
- queue usage,
- DB write throughput,
- query latency.

Mümkün olduğunca gerçekçi flow dağılımı kullan.

---

# 46. QUERY BENCHMARK

Özellikle aşağıdaki sorguları benchmark et:

- Last 15 min Top Sources
- Last 24h Top Destinations
- Last 7d Traffic Trend
- IP search
- ASN aggregation
- Country aggregation
- protocol aggregation
- exporter statistics

Sonuçları raporla.

---

# 47. REGRESSION ÖNLEME

Her optimizasyon sonrasında doğruluğu kontrol et.

Performans için veri doğruluğunu bozma.

Flow sayısı, packet sayısı ve byte toplamları doğru olmalıdır.

---

# 48. RESPONSIVE TASARIM

Ana kullanım masaüstü olacaktır.

Öncelik:

1920x1080
2560x1440

ekranlardır.

Ancak interface daha küçük notebook ekranlarında da kullanılabilir olmalıdır.

Mobil optimizasyon ana öncelik değildir.

---

# 49. NAVIGATION

Menü yapısını mümkün olduğunca sade tut.

Örnek:

Overview
Analytics
Flow Explorer
Traffic
Exporters
Reports
System

Traffic altında:

Applications
Protocols
Countries
ASNs
Interfaces

gibi alt bölümler olabilir.

Gerçek bilgi mimarisini mevcut uygulamaya göre sen belirle.

---

# 50. DASHBOARD CARD SPRAWL YAPMA

Ana dashboard'a 40 farklı KPI kartı koyma.

Kritik KPI'ları göster.

Diğer detayları ilgili analiz ekranlarına taşı.

---

# 51. EMPTY STATE / ERROR STATE

Arayüzün her ekranı aşağıdaki durumlarda düzgün davranmalıdır:

- henüz flow gelmediğinde,
- exporter offline olduğunda,
- query sonucu boş olduğunda,
- database erişilemediğinde,
- API timeout olduğunda.

Kullanıcı boş ekran veya teknik stack trace görmemelidir.

---

# 52. LOADING STATE

Yavaş sorgularda:

- skeleton,
- progress state,
- partial rendering

kullan.

Kullanıcı uygulamanın donduğunu düşünmemelidir.

---

# 53. URL STATE

Mümkünse Flow Explorer ve Analytics filtrelerini URL'e yansıt.

Böylece analiz linkleri paylaşılabilir.

Örneğin:

/analytics?src=10.0.0.0/8&protocol=tcp&range=24h

---

# 54. EXPORTLARDA FİLTRE KORUMA

Kullanıcı belirli filtrelerle analiz yaptıysa export aynı filtreleri ve zaman aralığını kullanmalıdır.

Export dosyasına mümkünse query metadata ekle.

Örneğin:

Time Range
Filters
Group By
Generated At

---

# 55. PROJEDE KIRIK VE YARIM ÖZELLİK BIRAKMA

Bir özelliğin backend'i varsa ama UI'ı yoksa değerlendir.

UI'ı varsa fakat backend'i mock ise tamamla veya kaldır.

"Coming Soon", dummy button, sahte grafik veya mock telemetry bırakma.

Ürün çalışır durumda olmalıdır.

---

# 56. TASARIM ÖZGÜRLÜĞÜ

Mevcut UI kötü tasarlanmışsa mevcut yapıya bağlı kalmak zorunda değilsin.

Gerekiyorsa dashboard ve analiz ekranlarını yeniden düzenle.

Ancak gereksiz framework migration yapma.

Ana amaç çalışan ürünü iyileştirmektir.

---

# 57. UYGULAMA SIRASI

Çalışmayı şu sırayla yap:

### Phase 1 — Audit

Mevcut sistemi tamamen analiz et.

### Phase 2 — Cleanup

Gereksiz:

- features,
- components,
- endpoints,
- dead code,
- dependencies

temizle.

### Phase 3 — Architecture

Flow ingestion, storage ve query mimarisini iyileştir.

### Phase 4 — Analytics Engine

Eksik analizleri oluştur.

### Phase 5 — UI/UX

Dashboard ve analiz ekranlarını geliştir.

### Phase 6 — Reporting

PDF, XLSX, CSV ve JSON export mekanizmalarını tamamla.

### Phase 7 — Performance

Benchmark ve profiling yap.

### Phase 8 — Testing

Bütün testleri çalıştır ve sorunları düzelt.

### Phase 9 — Final Review

Ürünü son kez:

- usability,
- correctness,
- speed,
- visual quality

açısından değerlendir.

---

# 58. ÇALIŞMA PRENSİBİ

Senden yalnızca analiz raporu istemiyorum.

Tespit ettiğin sorunları mümkün olduğu ölçüde doğrudan kaynak kod üzerinde düzelt.

Eksik özellikleri uygula.

Gereksiz özellikleri kaldır.

Gerekli refactoring işlemlerini gerçekleştir.

Kod değişikliklerinden sonra uygulamayı:

- build et,
- test et,
- lint et,
- mümkünse benchmark et,
- çalıştır.

Bir noktada hata alırsan görevi bırakma.

Hatanın kök nedenini araştır ve çöz.

---

# 59. MEVCUT ÇALIŞAN ÖZELLİKLERİ BOZMA

Refactoring sırasında mevcut fonksiyonları koru.

Bir özelliği kaldıracaksan bunun ürün odağı açısından gereksiz olduğundan emin ol.

Backward compatibility gerekli alanlarda korunmalıdır.

---

# 60. VERİ DOĞRULUĞU

Analytics sonuçları yalnızca güzel görünmemeli, matematiksel olarak doğru olmalıdır.

Aşağıdaki değerleri doğrula:

- bytes,
- packets,
- flows,
- unique source,
- unique destination,
- protocol ratios,
- Top-N,
- time bucket aggregations.

---

# 61. SONUÇTA BEKLENEN ÜRÜN

Son durumda ürün şu sorulara çok hızlı cevap verebilmelidir:

- Ağımda ne kadar trafik var?
- Trafik zaman içerisinde nasıl değişiyor?
- En fazla trafik kim üretiyor?
- Trafik nereye gidiyor?
- En yoğun destination hangisi?
- En yoğun source hangisi?
- Hangi application en fazla bandwidth kullanıyor?
- Hangi protocol en fazla kullanılıyor?
- Hangi ASN'lere trafik gidiyor?
- Hangi ülkelere trafik gidiyor?
- Hangi exporter ne kadar veri gönderiyor?
- Hangi interface en yoğun?
- Belirli bir IP ne kadar trafik üretmiş?
- Belirli iki IP arasında ne kadar trafik olmuş?
- Geçen hafta ile bu hafta arasında ne değişmiş?
- Belirli zaman aralığında network kullanımının özeti nedir?
- Bu analizleri PDF veya Excel olarak nasıl paylaşabilirim?

Bu soruların cevapları mümkün olduğunca birkaç saniye içinde alınabilmelidir.

---

# 62. BAŞARI KRİTERLERİ

Bu geliştirme tamamlandığında:

1. Uygulama çok daha sade ve profesyonel görünmeli.
2. Gereksiz özellikler kaldırılmış olmalı.
3. Flow Analytics ürünün merkezine alınmış olmalı.
4. Dashboard gerçek karar verme değeri taşımalı.
5. Çok büyük flow dataset'lerinde çalışabilecek mimari oluşturulmalı.
6. Query performansı iyileşmiş olmalı.
7. Flow ingestion performansı korunmuş veya artırılmış olmalı.
8. Reporting güçlü hale gelmiş olmalı.
9. PDF / Excel / CSV export kullanılabilir olmalı.
10. UI modern ve kurumsal görünmeli.
11. CISO / Executive görünümü bulunmalı.
12. Teknik analistler için güçlü Flow Explorer bulunmalı.
13. Zaman bazlı analiz ve karşılaştırma bulunmalı.
14. Kod kalitesi belirgin şekilde yükselmiş olmalı.
15. Testler başarılı olmalı.
16. Ürün NDR'a dönüşmeden flow analytics görevine odaklanmalı.

---

# 63. SON TESLİM RAPORU

Çalışmanın sonunda kapsamlı bir rapor hazırla.

Raporda aşağıdaki bölümleri kullan:

## 1. Initial Assessment

İlk durumda tespit ettiğin temel problemler.

## 2. Removed Features

Kaldırılan gereksiz özellikler ve nedenleri.

## 3. Architecture Changes

Backend, ingestion, storage ve query katmanlarında yapılan değişiklikler.

## 4. Analytics Improvements

Eklenen veya geliştirilen analizler.

## 5. UI/UX Improvements

Dashboard ve arayüz değişiklikleri.

## 6. Reporting Improvements

PDF, XLSX, CSV ve diğer export geliştirmeleri.

## 7. Performance Improvements

Performans optimizasyonları.

Mümkünse:

Before → After

karşılaştırması kullan.

## 8. Database Changes

Schema, index, partition veya aggregation değişiklikleri.

## 9. Security Fixes

Tespit edilen ve düzeltilen güvenlik problemleri.

## 10. Tests

Çalıştırılan testler ve sonuçları.

## 11. Benchmarks

Ingestion ve query benchmark sonuçları.

## 12. Remaining Technical Debt

Varsa halen iyileştirilmesi gereken noktalar.

## 13. Recommended Next Phase

Bir sonraki geliştirme turunda yapılması gerekenleri öncelik sırasıyla öner.

---

# 64. EN ÖNEMLİ PRENSİP

Her teknik ve tasarımsal kararda şu soruyu sor:

> "Bu değişiklik kullanıcının çok büyük miktardaki flow datasını daha hızlı, daha doğru ve daha anlaşılır şekilde analiz etmesine yardımcı oluyor mu?"

Cevap hayır ise özelliği ekleme.

Ürün özellik sayısıyla değil;

**hız, ölçeklenebilirlik, analiz gücü, veri doğruluğu, sorgulama kolaylığı ve görsel açıklıkla**

iyi olmalıdır.

---

# SON TALİMAT

Önce mevcut repository'yi analiz et.

Ardından yukarıdaki hedefler doğrultusunda gerekli değişiklikleri doğrudan uygula.

Yalnızca öneriler üretip durma.

Kod üzerinde çalış.

Gerekli dosyaları değiştir.

Gereksiz bölümleri kaldır.

Eksik bölümleri tamamla.

Build ve test hatalarını çöz.

Performansı doğrula.

UI'ın gerçek verilerle çalıştığını kontrol et.

Mock veya placeholder özellik bırakma.

Bütün geliştirmeler tamamlandıktan sonra sistemi tekrar bütünsel olarak değerlendir ve geliştirme öncesi / sonrası farkları son raporda açık şekilde belirt.

Ana hedef:

**Dünyadaki en kullanışlı, hızlı, ölçeklenebilir ve görsel açıdan güçlü merkezi flow toplama ve flow analytics ürünlerinden birini oluşturmak.**