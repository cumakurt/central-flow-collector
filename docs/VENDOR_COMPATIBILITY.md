# Vendor compatibility

The onboarding API includes 24 vendor profiles covering 20 vendor families,
plus generic IPFIX and sFlow profiles. Profiles select a supported wire format
and collector port; they are not firmware or appliance certifications. The
decoder is template-driven and does not require a vendor allowlist. Any
exporter using the supported standard formats can send traffic, including
vendors not named below.

## Routers, switches, and gateways

- Cisco IOS/IOS XE: NetFlow v5/v9 and IPFIX; Flexible NetFlow templates and
  scoped options use the shared template decoder. Cisco ASA/Secure Firewall
  NSEL: v9 event, NAT, and standard byte fields; private event fields remain
  in custom metadata. See [Cisco export formats](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html)
  and [ASA NSEL](https://www.cisco.com/c/en/us/td/docs/security/asa/special/netflow/asa_netflow.html).
- Juniper: J-Flow v9 and inline IPFIX, including IPv4/IPv6, interfaces, AS,
  and options. See [Junos IPFIX templates](https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/topics/concept/services-ipfix-flow-template-flow-aggregation-configuring.html).
- Huawei: select NetStream v5/v8/v9 or standard IPFIX on capable models.
  NetFlow/NetStream v8 aggregation schemes are normalized when the exporter
  emits the Cisco-compatible record layouts. See [NetStream formats](https://support.huawei.com/enterprise/en/doc/EDOC1100466181/b81c591d/netstream-description).
- H3C: NetStream v9/v10 (IPFIX). See [NetStream configuration](https://www.h3c.com/en/Support/Resource_Center/EN/Home/Public/00-Public/Technical_Documents/Configure___Deploy/Configuration_Guides/H3C_CG-29160/17/202509/2657425_294551_0.htm).
- MikroTik: Traffic Flow v5/v9/IPFIX. See [RouterOS Traffic Flow](https://help.mikrotik.com/docs/spaces/ROS/pages/21102653/Traffic%2BFlow).
- Nokia: cflowd v9/v10; select version 10 for the IPFIX listener. See [Nokia cflowd](https://documentation.nokia.com/sar/26-4-1/books/router-config/cflowd.html).
- Ubiquiti: standard IPFIX on gateways that expose NetFlow traffic logging.
  See [UniFi traffic logging](https://help.ui.com/hc/en-us/articles/32201256219799-Traffic-Flows-and-Traffic-Logging-in-UniFi-Network).

## Firewalls

- Fortinet FortiGate: NetFlow v9 standard IPv4/IPv6/NAT fields, sampler IDs
  and intervals, and application-ID/name options. Multiple application
  mappings with the same system scope coexist; application names and sampling
  metadata are selected independently. See [FortiOS templates](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/448589/netflow-templates).
- Palo Alto Networks: PAN-OS v9 IPv4/IPv6 and NAT64 fields, firewall events,
  App-ID and User-ID. Private v9 fields 56701/56702 are interpreted only when
  IE 346 identifies PEN 25461. See [PAN-OS templates](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/netflow-monitoring/netflow-templates).
- Check Point: Gaia v5/v9/IPFIX standard exports. See [Gaia NetFlow export](https://sc1.checkpoint.com/documents/R80.40/WebAdminGuides/EN/CP_R80.40_Gaia_AdminGuide/Topics-GAG/Netflow-Export.htm).
- SonicWall: standard IPFIX external reporting; private extensions are
  retained, not all application/static-table formats are interpreted. See
  [SonicOS external collector configuration](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7.0.1-device_appflow/Content/appflow-d-flow-reporting-user-config-netflow-v10.htm).

## sFlow switching platforms

Use sFlow v5 **packet sampling**, with a supported Ethernet or IPv4/IPv6 packet
record. Regular/expanded samples, interfaces, VLAN/QinQ, IP-over-MPLS,
fragments, IPv6 extensions, BGP gateway/AS-path metadata, and extended NAT
addresses are decoded. Counter-only polling is not traffic-flow collection.

- [Arista EOS](https://www.arista.com/en/um-eos/eos-sflow)
- [Aruba/HPE AOS-CX](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/PDF/ip_services_5420-6200.pdf)
- [Dell PowerSwitch OS10](https://www.dell.com/support/manuals/en-us/dell-emc-smartfabric-os10/smartfabric-os-user-guide-10-5-1/sflow?guid=guid-93aa2f81-48e8-4315-b71d-f20118a7be24&lang=en-us)
- [Extreme Networks ExtremeXOS / Switch Engine](https://documentation.extremenetworks.com/exos_30.2.2/GUID-B01E96DB-4365-42AA-8E3F-29DB1E1A38F4.shtml)
- [NVIDIA/Mellanox Cumulus Linux](https://docs.nvidia.com/networking-ethernet-software/nvue-reference/Set-and-Unset-Commands/sFlow/)
- [Ruijie](https://community.ruijienetworks.com/forum.php?mod=viewthread&tid=6107)

## Virtual switching and load balancers

- VMware/Broadcom: standard IPFIX export from supported distributed switches.
  See [vSphere IPFIX](https://knowledge.broadcom.com/external/article/433680/what-is-netflowipfix-and-how-can-i-enabl.html).
- NetScaler/Citrix: AppFlow with IPFIX transport. Standard flow fields are
  decoded; HTTP/HDX/database-specific enterprise data remains custom metadata.
  Logstream is not IPFIX. See [AppFlow](https://docs.netscaler.com/en-us/citrix-adc/current-release/ns-ag-appflow-intro-wrapper-con.html).
- F5 BIG-IP: sFlow packet sampling and standard IPFIX/CGNAT event fields.
  HTTP-only sFlow transactions and all private event schemas are not traffic
  flows. See [BIG-IP sFlow](https://techdocs.f5.com/en-us/bigip-14-0-0/external-monitoring-of-big-ip-systems-implementations-14-0-0/monitoring-big-ip-system-traffic-with-sflow.html)
  and [IPFIX CGNAT templates](https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/bigip-external-monitoring-implementations-12-1-2/15.html).

## Counter semantics and validation

RFC 5103 reverse counters (PEN 29305) produce a separate reverse-direction
flow, while the IPFIX sequence counter still counts the original wire record
once. Unknown vendor counters and post-forwarding counters (IEs 23/24) are
retained as raw metadata rather than automatically added to forward bytes:
post-forwarding does not universally mean reverse-direction traffic.
Layer-4 payload counters likewise are not silently treated as Layer-3 bytes.

Synthetic regression fixtures cover FortiGate application/sampling options,
PAN-OS private namespace isolation/NAT64, RFC 5103 reverse counters, standard
template variations, and sFlow extended records. The onboarding test checks
every profile's protocol routing. No physical-device interoperability or
firmware certification was performed. Complete transport, record, and
information-element limits are listed in [protocol support](PROTOCOLS.md).
