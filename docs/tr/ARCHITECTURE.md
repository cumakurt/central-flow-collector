# Mimari

Kaynak: [ARCHITECTURE.md](../ARCHITECTURE.md)

Her UDP dinleyicisinin sınırlı paketi kuyruğu vardır; IPFIX dinleyicileri RFC
7011 çerçeveli TCP veya Linux SCTP akışlarını da kabul eder. Linux’ta `recvmmsg`
ile datagram toplama yapılabilir. Worker’lar NetFlow v1/v5/v7/v8/v9, IPFIX ve
sFlow verisini ortak `model.Flow` yapısına dönüştürür. Şablon durumu gönderici,
taşıma/kaynak portu, listener, observation domain ve template ID ile ayrılır.
Politika, zenginleştirme, analiz ve depolama sıralı akışta uygulanır; TLS/DTLS
collector önünde sonlandırılır.
