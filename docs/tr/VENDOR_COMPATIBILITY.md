# Üretici uyumluluğu

Kaynak: [VENDOR_COMPATIBILITY.md](../VENDOR_COMPATIBILITY.md)

Onboarding API; Cisco, Juniper, Huawei/H3C, MikroTik, Fortinet, Palo Alto,
Check Point, SonicWall, Arista, Aruba/HPE, Dell, Extreme, NVIDIA, Ruijie,
Nokia, VMware, NetScaler, F5 ve Ubiquiti dahil 20 üretici ailesini kapsar.
Profiller sertifikasyon değil, desteklenen wire format ve port seçicisidir.

Standart NetFlow/IPFIX/sFlow gönderen ve listede olmayan cihazlar da kabul
edilir. NetFlow v8 aggregation, IPFIX TCP/SCTP, enterprise IE ham saklama,
PAN-OS App-ID/User-ID, FortiGate options, NAT/VRF/firewall ve RFC 5103 reverse
counter davranışları protokol belgelerinde açıklanmıştır. Gerçek firmware
uyumluluğu için temsilî export paketleriyle doğrulama gerekir.
