package storage

func assetMetric(a AssetSummary, metric string) uint64 {
	switch metric {
	case "packets":
		return a.PacketsIn + a.PacketsOut
	case "flows":
		return a.Flows
	case "peers":
		return a.Peers
	default:
		return a.BytesIn + a.BytesOut
	}
}

func conversationMetric(c ConversationSummary, metric string) uint64 {
	switch metric {
	case "packets":
		return c.PacketsAB + c.PacketsBA
	case "flows":
		return c.Flows
	default:
		return c.BytesAB + c.BytesBA
	}
}

func conversationLess(a, b ConversationSummary) bool {
	if a.AIP != b.AIP {
		return a.AIP < b.AIP
	}
	if a.APort != b.APort {
		return a.APort < b.APort
	}
	if a.BIP != b.BIP {
		return a.BIP < b.BIP
	}
	if a.BPort != b.BPort {
		return a.BPort < b.BPort
	}
	return a.Protocol < b.Protocol
}
