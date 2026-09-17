# Performans

Kaynak: [PERFORMANCE.md](../PERFORMANCE.md)

v4; sınırlı listener/depolama kuyrukları, Linux’ta batch UDP okuma, IPFIX
TCP/SCTP mesaj çerçeveleme, worker sharding, yeniden kullanılabilir buffer’lar,
asenkron batch yazımı ve ClickHouse toplu sorgularını kullanır. `flowbench`
paket/akış hızı, gecikme, allocation ve GC değerlerini ölçer; bu ölçümler
donanım kapasitesi garantisi değildir. SCTP toplama Linux ile sınırlıdır.
