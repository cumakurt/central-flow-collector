package api

import (
	"central-flow-collector/internal/model"
	"net"
	"sort"
	"strings"
)

type topoNode struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Kind    string `json:"kind"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}
type topoEdge struct {
	Source  string `json:"source"`
	Target  string `json:"target"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}
type topologyResult struct {
	Mode          string     `json:"mode"`
	Nodes         []topoNode `json:"nodes"`
	Edges         []topoEdge `json:"edges"`
	FlowsExamined int        `json:"flows_examined"`
	Bounded       bool       `json:"bounded"`
	Note          string     `json:"note"`
}

type topoAccum struct{ bytes, packets, flows uint64 }

func subnetLabel(ipstr, explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	ip := net.ParseIP(ipstr)
	if ip == nil {
		return "unknown"
	}
	if v4 := ip.To4(); v4 != nil {
		return net.IP(v4).Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
func topoEndpoint(f model.Flow, mode string, src bool) string {
	switch mode {
	case "site":
		if src && f.SrcSite != "" {
			return f.SrcSite
		}
		if !src && f.DstSite != "" {
			return f.DstSite
		}
		if src {
			return subnetLabel(f.SrcIP, f.SrcPrefix)
		}
		return subnetLabel(f.DstIP, f.DstPrefix)
	case "subnet":
		if src {
			return subnetLabel(f.SrcIP, f.SrcPrefix)
		}
		return subnetLabel(f.DstIP, f.DstPrefix)
	default:
		if src {
			return f.SrcIP
		}
		return f.DstIP
	}
}
func buildTopology(flows []model.Flow, mode string, maxNodes int, minBytes uint64) topologyResult {
	if mode != "site" && mode != "subnet" && mode != "host" {
		mode = "site"
	}
	if maxNodes < 10 {
		maxNodes = 40
	}
	if maxNodes > 200 {
		maxNodes = 200
	}
	nodes := map[string]*topoAccum{}
	edges := map[string]*topoAccum{}
	for _, f := range flows {
		a, b := topoEndpoint(f, mode, true), topoEndpoint(f, mode, false)
		if a == "" || b == "" || a == "unknown" || b == "unknown" {
			continue
		}
		for _, id := range []string{a, b} {
			if nodes[id] == nil {
				nodes[id] = &topoAccum{}
			}
			nodes[id].bytes += f.Bytes
			nodes[id].packets += f.Packets
			nodes[id].flows++
		}
		if a == b {
			continue
		}
		key := a + "\x00" + b
		if edges[key] == nil {
			edges[key] = &topoAccum{}
		}
		edges[key].bytes += f.Bytes
		edges[key].packets += f.Packets
		edges[key].flows++
	}
	ids := make([]string, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return nodes[ids[i]].bytes > nodes[ids[j]].bytes })
	if len(ids) > maxNodes {
		ids = ids[:maxNodes]
	}
	keep := map[string]bool{}
	outNodes := make([]topoNode, 0, len(ids))
	for _, id := range ids {
		keep[id] = true
		x := nodes[id]
		outNodes = append(outNodes, topoNode{ID: id, Label: id, Kind: mode, Bytes: x.bytes, Packets: x.packets, Flows: x.flows})
	}
	outEdges := make([]topoEdge, 0)
	for k, x := range edges {
		if x.bytes < minBytes {
			continue
		}
		p := strings.SplitN(k, "\x00", 2)
		if len(p) != 2 || !keep[p[0]] || !keep[p[1]] {
			continue
		}
		outEdges = append(outEdges, topoEdge{Source: p[0], Target: p[1], Bytes: x.bytes, Packets: x.packets, Flows: x.flows})
	}
	sort.Slice(outEdges, func(i, j int) bool { return outEdges[i].Bytes > outEdges[j].Bytes })
	if len(outEdges) > 400 {
		outEdges = outEdges[:400]
	}
	return topologyResult{Mode: mode, Nodes: outNodes, Edges: outEdges, FlowsExamined: len(flows), Bounded: true, Note: "Topology is aggregated server-side from a bounded query window (maximum 5,000 matching flows per request)."}
}
