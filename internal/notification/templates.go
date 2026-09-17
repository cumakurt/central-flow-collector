package notification

func RuleTemplates() []RuleDefinition {
	base := RuleDefinition{Name: "Specific Communication Observed", Kind: "match", Condition: Condition{Op: "eq", Field: "protocol", Values: []string{"6"}}, Metric: "flows", Operator: "gt", Threshold: 0, WindowSeconds: 300, IntervalSeconds: 60, CooldownSeconds: 1800, Recovery: true, Priority: "warning", GroupBy: []string{"src_ip", "dst_ip", "dst_port"}}
	rules := []RuleDefinition{base}
	seasonal := base
	seasonal.Name = "Seasonal Traffic Deviation"
	seasonal.Kind = "seasonal"
	seasonal.Metric = "bytes"
	seasonal.Threshold = 4
	seasonal.MinimumCurrent = 1_000_000
	seasonal.WindowSeconds = 3600
	seasonal.IntervalSeconds = 3600
	seasonal.ForSeconds = 3600
	seasonal.CooldownSeconds = 3600
	seasonal.GroupBy = []string{"exporter"}
	recovery := 2.0
	seasonal.RecoveryThreshold = &recovery
	rules = append(rules, seasonal)
	x := base
	x.Name = "Exporter Offline"
	x.Kind = "absence"
	x.Condition = Condition{Op: "eq", Field: "exporter", Values: []string{"127.0.0.1"}}
	x.WindowSeconds = 600
	x.GroupBy = nil
	x.Priority = "high"
	rules = append(rules, x)
	x = base
	x.Name = "Traffic Threshold"
	x.Kind = "aggregate"
	x.Metric = "bytes"
	x.Threshold = 10e9
	x.WindowSeconds = 900
	rules = append(rules, x)
	x = base
	x.Name = "DNS Volume Increase"
	x.Kind = "comparison"
	x.Condition = Condition{Op: "eq", Field: "dst_port", Values: []string{"53"}}
	x.Metric = "bytes"
	x.Threshold = 100
	x.MinimumCurrent = 1e9
	x.WindowSeconds = 900
	x.GroupBy = nil
	rules = append(rules, x)
	for _, spec := range []struct {
		name, metric string
		threshold    float64
	}{{"Collector Queue High", "queue_percent", 80}, {"ClickHouse Unavailable", "storage_unhealthy", 0}, {"Storage Capacity Low", "disk_percent", 90}} {
		x = base
		x.Name = spec.name
		x.Kind = "system"
		x.Metric = spec.metric
		x.Threshold = spec.threshold
		x.GroupBy = nil
		x.ForSeconds = 300
		rules = append(rules, x)
	}
	return rules
}
