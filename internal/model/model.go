package model

import "time"

func ApplicationName(f Flow) string {
	if f.AppName != "" {
		return f.AppName
	}
	if f.AppID != "" {
		return f.AppID
	}
	switch f.DstPort {
	case 20, 21:
		return "FTP"
	case 22:
		return "SSH"
	case 25, 465, 587:
		return "SMTP"
	case 53:
		return "DNS"
	case 80, 8080:
		return "HTTP"
	case 123:
		return "NTP"
	case 143, 993:
		return "IMAP"
	case 443, 8443:
		return "HTTPS"
	case 445:
		return "SMB"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5432:
		return "PostgreSQL"
	case 8123, 9000:
		return "ClickHouse"
	}
	return "Other"
}

type Flow struct {
	ReceiveTime   time.Time         `json:"receive_time"`
	CollectorNode string            `json:"collector_node,omitempty"`
	Tenant        string            `json:"tenant,omitempty"`
	StartTime     time.Time         `json:"start_time,omitempty"`
	EndTime       time.Time         `json:"end_time,omitempty"`
	Exporter      string            `json:"exporter"`
	Listener      string            `json:"listener"`
	Protocol      string            `json:"flow_protocol"`
	ObsDomain     uint32            `json:"observation_domain,omitempty"`
	SrcIP         string            `json:"src_ip,omitempty"`
	DstIP         string            `json:"dst_ip,omitempty"`
	SrcPort       uint16            `json:"src_port,omitempty"`
	DstPort       uint16            `json:"dst_port,omitempty"`
	IPProtocol    uint8             `json:"ip_protocol,omitempty"`
	Packets       uint64            `json:"packets,omitempty"`
	Bytes         uint64            `json:"bytes,omitempty"`
	TCPFlags      uint16            `json:"tcp_flags,omitempty"`
	TOS           uint8             `json:"tos,omitempty"`
	DSCP          uint8             `json:"dscp,omitempty"`
	ECN           uint8             `json:"ecn,omitempty"`
	IngressIf     uint32            `json:"ingress_if,omitempty"`
	EgressIf      uint32            `json:"egress_if,omitempty"`
	NextHop       string            `json:"next_hop,omitempty"`
	SrcAS         uint32            `json:"src_as,omitempty"`
	DstAS         uint32            `json:"dst_as,omitempty"`
	SrcASName     string            `json:"src_as_name,omitempty"`
	DstASName     string            `json:"dst_as_name,omitempty"`
	SrcCountry    string            `json:"src_country,omitempty"`
	DstCountry    string            `json:"dst_country,omitempty"`
	SrcSite       string            `json:"src_site,omitempty"`
	DstSite       string            `json:"dst_site,omitempty"`
	SrcPrefix     string            `json:"src_prefix,omitempty"`
	DstPrefix     string            `json:"dst_prefix,omitempty"`
	VLAN          uint16            `json:"vlan,omitempty"`
	SrcMAC        string            `json:"src_mac,omitempty"`
	DstMAC        string            `json:"dst_mac,omitempty"`
	NATSrcIP      string            `json:"nat_src_ip,omitempty"`
	NATDstIP      string            `json:"nat_dst_ip,omitempty"`
	NATSrcPort    uint16            `json:"nat_src_port,omitempty"`
	NATDstPort    uint16            `json:"nat_dst_port,omitempty"`
	Direction     uint8             `json:"direction,omitempty"`
	Sampling      uint32            `json:"sampling_rate,omitempty"`
	Sequence      uint32            `json:"sequence,omitempty"`
	AppID         string            `json:"application_id,omitempty"`
	AppName       string            `json:"application_name,omitempty"`
	VRF           string            `json:"vrf,omitempty"`
	Custom        map[string]string `json:"custom,omitempty"`
}

type PacketContext struct {
	Exporter   string
	SourcePort uint16
	Listener   string
	Protocol   string
	RuleID     string
	DestPort   int
	Received   time.Time
}

type DecodeResult struct {
	Flows             []Flow
	Options           []Flow
	DataRecords       int
	TemplatesAdded    int
	MissingTemplate   bool
	Sequence          uint32
	ObservationDomain uint32
}

type ExporterStat struct {
	Address          string    `json:"address"`
	Protocol         string    `json:"protocol"`
	Listener         string    `json:"listener"`
	Allowed          bool      `json:"allowed"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	PacketsReceived  uint64    `json:"packets_received"`
	PacketsRejected  uint64    `json:"packets_rejected"`
	Flows            uint64    `json:"flows"`
	DecodeErrors     uint64    `json:"decode_errors"`
	MissingTemplates uint64    `json:"missing_templates"`
	SequenceGaps     uint64    `json:"sequence_gaps"`
	LastSequence     uint32    `json:"last_sequence"`
}

type RejectionStat struct {
	SourceIP  string    `json:"source_ip"`
	Protocol  string    `json:"protocol"`
	Listener  string    `json:"listener"`
	Packets   uint64    `json:"packets_rejected"`
	Bytes     uint64    `json:"bytes_rejected"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Reason    string    `json:"reason"`
}

type Alert struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	Reason    string    `json:"reason"`
	Evidence  string    `json:"evidence"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     uint64    `json:"count"`
	Entity    string    `json:"entity"`
	Observed  float64   `json:"observed"`
	Threshold float64   `json:"threshold"`
	Status    string    `json:"status"`
}
