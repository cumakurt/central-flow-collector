# Central Flow Collector

<div align="center">

**NetFlow, IPFIX ve sFlow için yüksek performanslı ağ akışı toplama ve operasyonel analiz platformu**

[![Sürüm](https://img.shields.io/badge/sürüm-4.0.0-2563eb?style=flat-square)](project.json)
[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat-square&logo=go&logoColor=white)](go.mod)
[![Lisans](https://img.shields.io/badge/lisans-AGPL--3.0--only-7c3aed?style=flat-square)](LICENSE)
[![Platformlar](https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-0f172a?style=flat-square&logo=linux&logoColor=white)](#kurulum)

[English](README.md) · [Türkçe](README.tr.md) · [Dokümantasyon](docs/) · [OpenAPI](openapi.yaml) · [Sorun bildir](https://github.com/cumakurt/central-flow-collector/issues)

</div>

Central Flow Collector; ağ akışı telemetrisini alan, ortak bir modele dönüştüren, yerel olarak veya ClickHouse üzerinde saklayan ve aranabilir operasyonel bilgiye çeviren, kendi altyapınızda çalıştırabileceğiniz tek organizasyonlu bir platformdur. UDP, TCP ve Linux SCTP toplayıcılarını, web portalını, kimlik doğrulamalı API'yi, raporlamayı, sağlık izlemeyi ve tekrarlanabilir performans araçlarını tek bir statik Go dağıtımında birleştirir.

Ürün ağ akışı görünürlüğü ve kapasite analizi için geliştirilmiştir. Paket içeriği saklamaz; NDR, SIEM, SOAR, IDS/IPS veya paket yakalama sistemi değildir.

## İçindekiler

- [Öne çıkanlar](#öne-çıkanlar)
- [Yetenekler](#yetenekler)
- [Desteklenen protokoller](#desteklenen-protokoller)
- [Mimari](#mimari)
- [Hızlı başlangıç](#hızlı-başlangıç)
- [Kurulum](#kurulum)
- [Yapılandırma](#yapılandırma)
- [Kimlik doğrulama ve API](#kimlik-doğrulama-ve-api)
- [Operasyon ve güvenlik](#operasyon-ve-güvenlik)
- [Performans ve boyutlandırma](#performans-ve-boyutlandırma)
- [Geliştirme](#geliştirme)
- [Sorun giderme](#sorun-giderme)
- [Dokümantasyon](#dokümantasyon)
- [Lisans](#lisans)

## Öne çıkanlar

- **Tek ve normalleştirilmiş görünüm:** NetFlow v1/v5/v7/v8/v9, IPFIX ve sFlow verileri aynı sorgu ve görselleştirme modelinde birleşir.
- **Operasyonel ayrıntıya inme:** panolardan ve Top-N sıralamalarından konuşmalara, uç noktalara, ağlara ve ham kayıtlara filtreleri koruyarak ilerleyebilirsiniz.
- **Sunucu tarafında analiz:** toplamlar, benzersiz varlıklar, uyarlanabilir zaman serileri, matrisler, dönem karşılaştırması, P95 bant genişliği ve tepe aralıkları depolamaya yakın hesaplanır.
- **Depolama seçeneği:** bağımlılıksız yerel JSONL ile başlayabilir, yüksek hacimli ve uzun süreli saklama için ClickHouse kullanabilirsiniz.
- **Sınırlı kaynak kullanımı:** dinleyici/depolama kuyrukları, analiz kardinalitesi, sonuç boyutları ve sorgu süreleri açık sınırlarla yönetilir.
- **Üretim kontrolleri:** RBAC, MFA/passkey, OIDC, LDAP, kapsamlı API token'ları, gönderici politikası, denetim bütünlüğü, yedekleme, bildirimler ve ClickHouse spool desteği bulunur.
- **Taşınabilir dağıtım:** amd64 ve arm64 için statik Linux ikilileri ile systemd, Docker Compose ve Helm dosyaları sağlanır.

## Yetenekler

### Toplama ve normalleştirme

- Yapılandırılabilir worker, alma tamponu, kuyruk ve batch boyutlarına sahip eş zamanlı UDP dinleyicileri ile çerçevelenmiş IPFIX TCP/SCTP dinleyicileri.
- NetFlow v1/v5/v7/v8/v9, IPFIX/NetFlow v10 ve sFlow v5 çözümleme.
- Cisco uyumlu NetFlow v8 toplama şemaları 1–14, toplu sayaç ve anahtarlarla normalleştirilir.
- NetFlow v9/IPFIX şablonlarının gönderici, taşıma, kaynak portu, dinleyici ve observation domain bazında ayrılması; kapsamlı seçenek metadatası.
- Kaynak sağladığında adres, port, protokol, sayaç, arayüz, ASN, ülke, site, uygulama, NAT alanı, TCP bayrağı ve gönderici bilgisini kapsayan ortak model.
- CIDR tabanlı Geo/ASN/site zenginleştirme ve genel IP adresleri için isteğe bağlı uzak kaynak.
- Gönderici izin/engelleme politikası, paket hız sınırı, tekilleştirme ve sınırlı analiz durumu.

### Keşif ve analiz

- Aynı toplu sorgu katmanını kullanan yönetici ve analist panoları.
- Sunucu tarafı filtreleme, cursor sayfalama, kayıtlı görünümler, URL durumu, ayrıntıya inme ve CSV/JSON dışa aktarma sunan Flow Explorer.
- En çok trafik üretenler, trafik eğilimleri, Service Timeline, Service Mix, saatlik ısı haritası, çift yönlü konuşmalar, trafik matrisi, yönlendirme, QoS/DSCP, NAT ve alan kapsamı.
- Uç nokta, eş, alt ağ, ASN, ülke, uygulama, protokol, arayüz, gönderici ve IP odaklı analizler.
- Kapasite görünümü, trafik baseline/sapma, dağılım analizi, P95 bant genişliği ve tepe zaman aralıkları.
- Doğrusal, logaritmik ve otomatik ölçekle aynı grafikte sekize kadar servis, port, IP protokolü veya uygulama serisi.

### Raporlama ve operasyon

- Etkin zaman aralığı ve filtrelerle PDF, XLSX, CSV ve JSON raporları.
- Duraklatma/devam ettirme, şimdi çalıştırma, dosya saklama, e-posta ve webhook teslimatı olan günlük, haftalık ve aylık raporlar.
- Dinleyici, gönderici, kuyruk, decoder, depolama ve node sağlık görünürlüğü.
- Bildirim kanalları, bütünlük zincirli denetim logları, yönetim, yedekleme/geri yükleme ve onarım kontrolü.
- ClickHouse geçici olarak kullanılamadığında CRC korumalı dayanıklı spool/WAL tekrar oynatma.
- Doğrulama ve performans ölçümü için `flowgen`, `flowbench`, `querybench` ve `chbench`.

## Desteklenen protokoller

| Protokol | Taşıma | Durum | Varsayılan port | Açıklama |
| --- | --- | --- | ---: | --- |
| NetFlow v5 | UDP | Destekleniyor | `2055` | Sabit IPv4 kayıtları ve örnekleme bilgisi |
| NetFlow v1 / v7 | UDP | Çözümleme destekleniyor | `2055` | Eski sabit IPv4 kayıtları; v7 geçerlilik bayrakları metadata olarak korunur |
| NetFlow v8 | UDP | Çözümleme destekleniyor | `2055` | Cisco toplama şemaları 1–14; toplu sayaç ve anahtarlar |
| NetFlow v9 | UDP | Temel destek | `2055` | Şablon/veri setleri ve yaygın bilgi öğeleri |
| IPFIX / NetFlow v10 | UDP, TCP, SCTP | Destekleniyor | `4739` | Şablonlar, kurumsal IE'ler, değişken alanlar, options ve stream çerçeveleme |
| sFlow v5 | UDP | Temel destek | `6343` | Flow/expanded sample, IPv4/IPv6 ve ham başlık metadatası |

Bağlantı profilleri Cisco, Juniper, Huawei/H3C, MikroTik, Fortinet, Palo Alto, Check Point, SonicWall, Arista, Aruba/HPE, Dell, Extreme, NVIDIA, Ruijie, Nokia, VMware, NetScaler, F5 ve Ubiquiti dahil 20 üretici ailesini kapsar. Uyumluluk desteklenen NetFlow/IPFIX/sFlow kipleri üzerinden sağlanır; özel alanların yorumlanma kapsamı değişir. IPFIX UDP, TCP ve SCTP üzerinden; NetFlow v8 toplama şemalarıyla birlikte desteklenir. TLS/DTLS için dış sonlandırıcı gerekir. Ayrıntılar için [üretici uyumluluğuna](docs/VENDOR_COMPATIBILITY.md) ve [protokol desteğine](docs/PROTOCOLS.md) bakın.

## Mimari

```text
Yönlendiriciler / anahtarlar / problar
          │ UDP üzerinden NetFlow v1/v5/v7/v8/v9 · sFlow
          │ UDP, TCP veya SCTP üzerinden IPFIX
          ▼
┌─────────────────────────────────────────────────────────────┐
│ dinleyici → sınırlı kuyruk → decoder → normalleştirilmiş akış│
│                         ↓                                   │
│   politika → zenginleştirme → dedup → operasyonel analiz    │
│                         ↓                                   │
│                 asenkron depolama batch'leri                 │
└──────────────────────────┬──────────────────────────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
      Yerel JSONL                  ClickHouse
      basit / laboratuvar          ölçek / saklama / rollup
                                         │
                                  hata anında spool/WAL

Tarayıcı / API → kimlik doğrulama + RBAC
               → toplu sorgular → explorer / panolar / raporlar
```

Her dinleyicinin sınırlı paket kuyruğu vardır. Linux, datagramları `recvmmsg` ile toplu okuyabilir; decoder worker'ları paketleri normalleştirilmiş akışa dönüştürür. Depolama yazımları asenkrondur. Portal ile raporlar aynı analiz sözleşmesini kullanır. Ayrıntılar için [Mimari](docs/ARCHITECTURE.md) belgesine bakın.

## Hızlı başlangıç

`dist/` altında çalıştırmaya hazır Linux ikilileri bulunur. Yerel depolama ile başlatmak için:

```bash
cp config.example.yaml config.local.yaml
mkdir -p .local-data/enrichment

# config.local.yaml içinde storage.data_dir, security.bootstrap_file ve
# analytics.baseline_state_file değerlerini .local-data altına yönlendirin.
./dist/flowcollector-linux-amd64 config validate --config ./config.local.yaml
./dist/flowcollector-linux-amd64 run --config ./config.local.yaml
```

`http://127.0.0.1:8080` adresini açın. İlk çalıştırmada bootstrap yönetici bilgisi `security.bootstrap_file` konumuna yazılır. Giriş yapıp normal kullanıcı bilgisini oluşturun veya güncelleyin ve bootstrap dosyasını silin.

Örnek NetFlow v5 trafiği gönderin:

```bash
./dist/flowgen-linux-amd64 \
  -protocol netflow5 \
  -target 127.0.0.1:2055 \
  -rate 100 \
  -count 1000
```

Sunucunuzla eşleşen `amd64` veya `arm64` ikilisini seçin.

## Kurulum

### Otomatik systemd kurulumu

```bash
sudo ./install.sh
```

Yeni varsayılan kurulum servis kullanıcısını ve dizinleri oluşturur, sıkılaştırılmış systemd servisini kurar, ClickHouse'u Docker içinde başlatır, collector'ı yapılandırır ve sağlık doğrulaması yapar. Var olan kurulumlar geri dönüş snapshot'ı ile yerinde yükseltilir.

```bash
# Harici bağımlılık gerektirmeyen yerel JSONL depolama
sudo ./install.sh --local-storage

# Var olan kurulumu zorunlu tut ve yükseltme snapshot'ı al
sudo ./install.sh --upgrade

# Uzak ClickHouse kullan
sudo ./install.sh \
  --clickhouse-host clickhouse.example.net \
  --clickhouse-scheme https \
  --clickhouse-user flowcollector \
  --clickhouse-password-file /secure/clickhouse-password

# Son installer snapshot'ına dön
sudo ./install.sh --rollback
```

| Amaç | Varsayılan yol |
| --- | --- |
| İkili | `/usr/local/bin/flowcollector` |
| Yapılandırma | `/etc/flowcollector/config.yaml` |
| Kalıcı veri | `/var/lib/flowcollector` |
| Loglar | `/var/log/flowcollector` ve systemd journal |
| Servis birimi | `/etc/systemd/system/flowcollector.service` |

TLS, kümeleme, ClickHouse, dizin ve servis seçenekleri için `sudo ./install.sh --help` kullanın. [Debian](packaging/deb/README.md) ve [RPM](packaging/rpm/README.md) paket notları ayrıca sunulur.

### Docker Compose

```bash
cd deploy/docker
export CLICKHOUSE_PASSWORD='guclu-bir-parola-ile-degistirin'
docker compose up --build -d
docker compose ps
```

Geliştirme/POC stack'i ClickHouse'u çalıştırır; TCP `8080` ile UDP `2055`, `4739` ve `6343` portlarını yayınlar. Üretim öncesinde kimlik bilgilerini, TLS'i, bind adreslerini, volume'leri, kaynak sınırlarını ve yedeklemeyi gözden geçirin.

### Kubernetes / Helm

```bash
helm upgrade --install flowcollector \
  deploy/helm/central-flow-collector \
  --namespace flowcollector \
  --create-namespace
```

Chart varsayılan olarak tek replica, `LoadBalancer` servisi, yerel depolama ve 20 GiB kalıcı volume kullanır. Üretim sırlarını Kubernetes Secret veya harici secret manager ile sağlayın.

### Hazır paketler

`dist/` dizininde Linux amd64/arm64 ikilileri, Debian paketleri, RPM, checksum, lisans ve sürüm bilgileri bulunur:

```bash
cd dist
sha256sum --check checksums.txt
```

## Yapılandırma

[`config.example.yaml`](config.example.yaml) temel referanstır. Her değişikliği yeniden başlatmadan önce doğrulayın:

```bash
flowcollector config validate --config /etc/flowcollector/config.yaml
```

| Bölüm | Amaç | Temel varsayılanlar |
| --- | --- | --- |
| `node` | Node kimliği ve bölgesi | boş/üretilen ID, `default` |
| `web` | Portal/API bind ve TLS | `127.0.0.1:8080`, TLS kapalı |
| `storage` | Yerel veya ClickHouse kalıcılığı | yerel, 7 gün saklama |
| `security` | Oturum, bootstrap, MFA ve sınırlar | varsayılan engelleme, 8 saat |
| `oidc`, `ldap` | Harici kimlik sağlayıcıları | kapalı |
| `logging` | Yapılandırılmış log | JSON, `info` |
| `enrichment` | CIDR Geo/ASN/site ve uzak sorgu | açık |
| `analytics` | Baseline, dedup ve kardinalite | baseline ve dedup açık |
| `notifications` | Webhook, Telegram, SMTP, syslog | ayarlanmamış |
| `cluster` | Heartbeat, global dedup ve mTLS | beklenen tek node |
| `listeners` | UDP veya IPFIX TCP/SCTP uçları, kuyruk ve worker ayarı | 2055, 4739, 6343 |

IPFIX stream dinleyicisi açıkça yapılandırılır; TCP ve SCTP, NetFlow veya
sFlow dinleyicileri için kabul edilmez:

```yaml
listeners:
  - name: ipfix-tcp
    bind: "0.0.0.0"
    port: 4739
    protocol: ipfix
    transport: tcp
    workers: 4
    queue_size: 8192
    batch_size: 16
    enabled: true
  # Linux üzerinde RFC 7011 SCTP göndericileri için transport: sctp kullanın.
```

Collector her stream'den bir tam IPFIX mesajı okur ve şablonları gönderici,
taşıma/kaynak portu, dinleyici, observation domain ve template ID bazında
ayırır. TLS/DTLS, dinleyicinin önünde bir proxy veya load balancer tarafından
sonlandırılmalıdır.

Secret değerlerini YAML içine yazmadan yükleyebilirsiniz:

```yaml
storage:
  clickhouse_password: "@env:FLOWCOLLECTOR_CLICKHOUSE_PASSWORD"

oidc:
  client_secret: "@file:/etc/flowcollector/secrets/oidc-client-secret"
```

Container kurulumlarında ortam değişkenleri ayarları geçersiz kılabilir; Compose dosyası adlandırmayı gösterir. Parola, token ve özel anahtarları kaynak kontrolüne eklemeyin. Ayrıntılar için [Yapılandırma](docs/CONFIGURATION.md).

### Depolama seçimi

**Yerel depolamayı** değerlendirme, laboratuvar, düşük/orta hız ve basit tek node kurulumu için kullanın. `storage.data_dir` altında JSONL segmentleri yazar ve veritabanı gerektirmez.

**ClickHouse'u** sürekli yüksek alım, hacimli ve uzun saklama, hızlı toplu analiz, rollup ve çoğaltılmış/dağıtık depolama için kullanın. Batch, kuyruk, sorgu sınırı, saklama ve spool boyutlarını hedef sunucuya göre ayarlayın. Başarılı UDP gönderimi paketin kabul edildiğini kanıtlamaz; collector drop'larını ve depolama sağlığını izleyin.

## Kimlik doğrulama ve API

Tek organizasyonda üç temel rol vardır:

| Rol | Amaçlanan erişim |
| --- | --- |
| `administrator` | Kullanıcı, ayar, politika, rapor, operasyon ve tüm analizler |
| `analyst` | İnceleme, analiz, görünüm ve izin verilen iş akışları |
| `read_only` | Pano, akış, sağlık ve rapor görevlerini görüntüleme |

Kimlik doğrulama yerel hesap, OIDC veya LDAP ile yapılabilir. Yerel hesaplar TOTP MFA ve WebAuthn/passkey destekler. API istemcileri süre sonu ve kaynak CIDR sınırı atanabilen, hash olarak saklanan kapsamlı Bearer token'ları kullanır.

Tam sözleşme [`openapi.yaml`](openapi.yaml) içindedir. Tarayıcı oturumları `fc_session` çerezini kullanır ve değişiklik isteklerinde `X-CSRF-Token` ister.

```bash
curl -H "Authorization: Bearer ${FLOWCOLLECTOR_TOKEN}" \
  "http://127.0.0.1:8080/api/v1/analytics?from=2026-09-17T08:00:00Z&to=2026-09-17T09:00:00Z"
```

Temel uçlar:

- `GET /health` ve `GET /ready` — canlılık ve hazırlık.
- `GET /api/v1/analytics` — toplamlar, Top-N boyutları ve zaman çizgisi.
- `GET /api/v1/flows/page` — cursor ile sayfalanan akışlar.
- `GET /api/v1/assets`, `/conversations`, `/ip/{ip}` — varlık analizi.
- `GET /api/v1/exporters/health` — gönderici sağlığı.
- `POST /api/v1/reports/export` — PDF/XLSX/CSV/JSON.
- `GET /api/v1/live/events` — kimlik doğrulamalı server-sent events.

Belgelenen analiz uçları dahilî RFC3339 `from`/`to` değerleri kullanır ve en fazla 31 günü kapsar. Filtre ve sınırlar için [API rehberine](docs/API.md) bakın.

### Komut satırından yönetim

```bash
flowcollector version
flowcollector health --url http://127.0.0.1:8080/health
flowcollector diagnostics --config /etc/flowcollector/config.yaml
flowcollector user reset-password --config /etc/flowcollector/config.yaml --username admin
flowcollector policy test --config /etc/flowcollector/config.yaml \
  --source 10.0.0.1 --protocol netflow --listener netflow --port 2055
flowcollector audit verify --config /etc/flowcollector/config.yaml
flowcollector repair check --config /etc/flowcollector/config.yaml
```

Tüm komutlar için `flowcollector --help` çalıştırın.

## Operasyon ve güvenlik

Canlılık için `/health`, bağımlılık hazırlığı için `/ready` kullanın. Portal; kuyruk kullanımını, paket/akış sayılarını, drop'ları, decoder hatalarını, gönderici sıra/şablon durumunu, depolama hatalarını ve desteklendiğinde kapasiteyi gösterir. Loglar varsayılan olarak JSON biçimindedir.

Diagnostics ve pprof varsayılan olarak kapalıdır. Yalnızca korunan yönetim arayüzünde açın. HTTP portalını güvenilmeyen ağa doğrudan sunmayın; TLS'i collector'da veya uygun reverse proxy'de sonlandırın.

### Yedekleme ve geri yükleme

```bash
# Yerel JSONL akışları dahil etmek için --include-flows ekleyin
flowcollector backup create \
  --config /etc/flowcollector/config.yaml \
  --output /secure/flowcollector-backup.tar.gz

flowcollector backup verify --archive /secure/flowcollector-backup.tar.gz

# Geri yüklemeden önce servisi durdurun
flowcollector restore \
  --config /etc/flowcollector/config.yaml \
  --archive /secure/flowcollector-backup.tar.gz \
  --force
flowcollector repair check --config /etc/flowcollector/config.yaml
```

Uygulama yedeği `--include-flows` verilmedikçe yerel akışları içermez ve ClickHouse tablolarını kopyalamaz. Üretim verisi için ClickHouse yedekleme/çoğaltma özelliklerini veya streaming JSONL için `clickhouse-backup` komutlarını kullanın. [Yedekleme ve geri yükleme](docs/BACKUP_RESTORE.md) belgesini okuyun.

### Üretim kontrol listesi

- Bootstrap kimlik bilgisini değiştirin ve dosyasını silin.
- Portalı TLS arkasına alın ve yönetim erişimini sınırlandırın.
- Secret değerlerini `@env:` veya korumalı `@file:` ile saklayın.
- Gönderici politikasını ve gerçekçi paket hız sınırlarını yapılandırın.
- UDP tamponlarını, kuyrukları, depolamayı ve saklamayı ölçülen trafiğe göre boyutlandırın.
- Dinleyici drop'larını depolama drop'larından ve yazma hatalarından ayrı izleyin.
- Yedeklemeyi yapılandırın ve üretim dışında geri yüklemeyi test edin.
- Bildirim uçlarını ve zamanlanmış rapor teslimatını doğrulayın.
- Sorun giderme dışında diagnostics özelliğini kapalı tutun.
- Üretim topolojisinde `flowbench` ve `querybench` çalıştırın.

Yüksek hacimli veya internete yakın kurulum öncesi [Güvenlik](docs/SECURITY.md), [Yönetim](docs/ADMINISTRATION.md) ve [Sorun giderme](docs/TROUBLESHOOTING.md) belgelerini okuyun.

## Performans ve boyutlandırma

Yerel depolama ile üretim analiz/dedup yollarının açık olduğu 5 vCPU AMD EPYC test ortamında, dört protokolün yoğun paket testleri dinleyici veya depolama drop'u olmadan yaklaşık **205–210 bin akış/saniye** düzeyine ulaştı. Bu sınıf için **sürekli ≤140 bin akış/saniye** ihtiyatlı hedef; yaklaşık **180 bin** yüksek kullanım, **200 bin** kritik düzeydir. Bu rakamlar tek ortamı tanımlar ve üretim garantisi değildir.

Yerel JSONL, ölçülen örnekte akış başına yaklaşık **451 bayt** kullanmıştır ve yüksek hızlı, çok günlük saklamada pratik sınıra dönüşür. Bu iş yükünde ClickHouse kullanıp gerçek altyapıda test yapın.

| Profil | İşlem / bellek | Depolama / ağ | Genel kullanım |
| --- | --- | --- | --- |
| Laboratuvar | 2 vCPU, 4 GiB | SSD | Değerlendirme ve düşük hızlı toplama |
| Standart | 4–6 modern vCPU, 8 GiB | SSD/NVMe | Genel tek node operasyonu |
| Yüksek trafik | 8 vCPU, 16 GiB | NVMe, 10 GbE | ClickHouse ile daha yüksek alım |

```bash
./dist/flowbench-linux-amd64 \
  -protocol netflow5 -target 127.0.0.1:2055 \
  -flows-per-packet 30 -workers 4 -pps 7000 -duration 30s

./dist/querybench-linux-amd64 -rows 50000 -iterations 5
```

Yöntem ve uyarılar için [Performans](docs/PERFORMANCE.md) belgesine bakın.

## Geliştirme

Gereksinimler: Go 1.23+, GNU Make ve `sha256sum` veya `shasum`. SBOM için Python 3, paketleme hedefleri için ilgili ek araçlar gerekir.

```bash
make build VERSION=4.0.0
make static VERSION=4.0.0
make test
make vet
make benchmark
make query-benchmark
make package VERSION=4.0.0 COMMIT=release-v4.0.0
make release-check
```

Web arayüzü bağımlılıksız JavaScript/CSS ile yazılır ve ikiliye gömülür; frontend kurulum veya bundle adımı yoktur.

```bash
go test ./...
go vet ./...
go build ./...
node --test \
  scripts/ui/state.test.cjs \
  scripts/ui/insight-state.test.cjs \
  scripts/ui/traffic-visuals-state.test.cjs
```

### Proje yapısı

```text
cmd/                    çalıştırılabilir araçların giriş noktaları
internal/               collector, decoder, API, auth, analiz ve depolama
internal/api/static/    gömülü web portalı
migrations/clickhouse/  ClickHouse şeması ve rollup'lar
deploy/                 Docker, Helm ve systemd dosyaları
docs/                   mimari, operasyon, API, güvenlik ve arayüz rehberleri
scripts/                derleme, paketleme, sürüm ve arayüz doğrulama araçları
testdata/                test fixture'ları
validation/              saklanan sürüm doğrulama kanıtları
dist/                    hazır ikililer ve paketler
```

## Sorun giderme

**Portal açılmıyor:** varsayılan bind `127.0.0.1` olduğu için yalnızca sunucudan erişilir. `web.bind`, servis durumu ve `flowcollector health` çıktısını kontrol edin. Loopback dışına açmadan önce TLS ve erişim kontrolü uygulayın.

**Servis grafikleri sıfır:** saklanan akışların kaynak/hedef portu içerdiğini doğrulayın. Yalnızca protokol kullanan görünümler ayrıca `ip_protocol` ister ve porttan tahmin yapmaz. Gönderici şablonlarını ve alan kapsamını kontrol edin.

**Akış gönderiliyor fakat görünmüyor:** protokolü, taşıma türünü, portu, güvenlik duvarını, gönderici politikasını, dinleyici sayaçlarını, decoder hatalarını, kuyruk drop'larını ve depolama sağlığını kontrol edin. IPFIX stream için `protocol: ipfix` ve `transport: tcp` veya `transport: sctp` kullanın; SCTP için Linux derlemesi gerekir. Gönderim başarılı görünse bile collector kabulü garanti edilmez.

**Zamanlanmış rapor teslim edilmiyor:** son görev sonucunu, e-posta seçeneğini ve alıcıları, bildirim kanallarını, SMTP/webhook ayarlarını ve denetim logunu inceleyin. Sunucudan DNS, TCP, TLS, kimlik doğrulama ve alıcı kabulünü test edin.

**Yükseltmeden sonra arayüz eski:** frontend ikiliye gömülüdür. Yeniden derlenen ikiliyle servisi başlatın ve tarayıcıda hard refresh yapın.

Ayrıntılı adımlar için [Sorun giderme](docs/TROUBLESHOOTING.md) belgesine bakın.

## Dokümantasyon

| Rehber | İçerik |
| --- | --- |
| [Kurulum](docs/INSTALL.md) | İkili, systemd, container ve sunucu konuları |
| [Yapılandırma](docs/CONFIGURATION.md) | Ayarlar, secret'lar ve depolama kontrolleri |
| [Mimari](docs/ARCHITECTURE.md) | Veri yolu, organizasyon modeli ve ölçek |
| [API](docs/API.md) / [OpenAPI](openapi.yaml) | Kimlik, uçlar, filtreler ve şema |
| [Analiz görünümleri](docs/ANALYSIS-VIEWS.md) | Yöntemler, sıralamalar ve ayrıntıya inme |
| [Güvenlik](docs/SECURITY.md) | Kimlik, token, tarayıcı kontrolleri ve denetim |
| [Yönetim](docs/ADMINISTRATION.md) | Günlük operasyon |
| [Yedekleme](docs/BACKUP_RESTORE.md) | Arşiv, doğrulama ve geri yükleme |
| [Performans](docs/PERFORMANCE.md) | Benchmark, boyutlandırma ve araçlar |
| [Container](docs/CONTAINERS.md) | Docker/Podman ve Kubernetes |
| [Kümeleme](docs/CLUSTER.md) | Heartbeat, global dedup ve mTLS |
| [4.0.0'a yükseltme](docs/UPGRADE_4.0.0.md) | Uyumluluk ve geçiş |
| [Sürüm durumu](docs/RELEASE_STATUS.md) | Güncel doğrulama durumu |

## Kapsam ve veriyi yorumlama

Akış telemetrisi, ağ cihazlarının dışa aktardığı metadata ve sayaçları içerir. Portalda gösterilen paket sayıları akış kayıtlarındaki sayaçlardır; saklanan paket içerikleri değildir. Baseline sapmaları trafik hacmi değişimini gösterir, saldırı sınıflandırması yapmaz. Uygulama, ülke, ASN, NAT, arayüz ve TCP alanlarını göndericinin gerçekten sağladığı bilgiye göre yorumlayın.

## Lisans

Telif hakkı 2026 Cuma KURT ve Central Flow Collector katkıda bulunanları.

Central Flow Collector, **GNU Affero General Public License sürüm 3 only** (`AGPL-3.0-only`) ile lisanslanmıştır. Tam koşullar için [LICENSE](LICENSE), atıf için [NOTICE](NOTICE) dosyasına bakın. Ağ üzerinden erişilebilen değiştirilmiş dağıtımlar, lisansın gerektirdiği karşılık gelen kaynak kodunu sunmalıdır.

Geliştiren: **Cuma KURT**  
[GitHub](https://github.com/cumakurt/central-flow-collector) · [LinkedIn](https://www.linkedin.com/in/cuma-kurt-34414917/) · [E-posta](mailto:cumakurt@gmail.com)
