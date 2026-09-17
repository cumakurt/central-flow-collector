package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"central-flow-collector/internal/adminops"
	"central-flow-collector/internal/analytics"
	"central-flow-collector/internal/api"
	"central-flow-collector/internal/audit"
	"central-flow-collector/internal/auth"
	"central-flow-collector/internal/buildinfo"
	"central-flow-collector/internal/cluster"
	"central-flow-collector/internal/collector"
	"central-flow-collector/internal/config"
	"central-flow-collector/internal/dedup"
	"central-flow-collector/internal/dr"
	"central-flow-collector/internal/engineering"
	"central-flow-collector/internal/enrichment"
	"central-flow-collector/internal/ldapauth"
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/notification"
	oidcauth "central-flow-collector/internal/oidc"
	"central-flow-collector/internal/policy"
	"central-flow-collector/internal/reporting"
	"central-flow-collector/internal/secrets"
	"central-flow-collector/internal/storage"
	"central-flow-collector/internal/workspace"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(run(os.Args[2:]))
	case "version":
		fmt.Printf("flowcollector %s\ncommit: %s\nbuild_time: %s\ngo: %s\n", buildinfo.Version, buildinfo.Commit, buildinfo.BuildTime, runtime.Version())
	case "config":
		configCmd(os.Args[2:])
	case "user":
		userCmd(os.Args[2:])
	case "policy":
		policyCmd(os.Args[2:])
	case "diagnostics":
		diagnostics(os.Args[2:])
	case "migrate":
		migrateCmd(os.Args[2:])
	case "health":
		healthCmd(os.Args[2:])
	case "backup":
		backupCmd(os.Args[2:])
	case "restore":
		restoreCmd(os.Args[2:])
	case "repair":
		repairCmd(os.Args[2:])
	case "clickhouse-backup":
		clickhouseBackupCmd(os.Args[2:])
	case "audit":
		auditCmd(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}
func usage() {
	fmt.Print(`Central Flow Collector

Usage:
  flowcollector run --config /etc/flowcollector/config.yaml
  flowcollector version
  flowcollector config validate --config FILE
  flowcollector user reset-password --config FILE --username admin [--password VALUE]
  flowcollector policy test --config FILE --source 10.0.0.1 --protocol netflow --listener netflow --port 2055
  flowcollector diagnostics --config FILE
  flowcollector migrate --config FILE
  flowcollector health --url http://127.0.0.1:8080/health
  flowcollector backup create --config FILE --output /secure/path/backup.tar.gz [--include-flows]
  flowcollector backup verify --archive /secure/path/backup.tar.gz
  flowcollector restore --config FILE --archive /secure/path/backup.tar.gz --force
  flowcollector repair check --config FILE
  flowcollector clickhouse-backup create --config FILE --output /secure/flows.jsonl.gz [--from RFC3339 --to RFC3339]
  flowcollector clickhouse-backup verify --archive /secure/flows.jsonl.gz
  flowcollector clickhouse-backup restore --config FILE --archive /secure/flows.jsonl.gz --force
  flowcollector audit verify --config FILE
  flowcollector audit export --config FILE --output /secure/audit.jsonl
`)
}
func cfgFlag(fs *flag.FlagSet) *string {
	return fs.String("config", envOr("FLOWCOLLECTOR_CONFIG", "/etc/flowcollector/config.yaml"), "configuration file")
}
func run(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cp := cfgFlag(fs)
	_ = fs.Parse(args)
	c, err := config.Load(*cp)
	fatalIf(err)
	fatalIf(secrets.Apply(&c))
	// A portal-scheduled metadata restore is executed before any stateful
	// subsystem opens files or listeners. The request can only reference an
	// archive inside the protected data-dir backup directory.
	if req, re := adminops.LoadPendingRestore(c.Storage.DataDir); re == nil {
		backupDir := filepath.Join(c.Storage.DataDir, "backups")
		rel, rerr := filepath.Rel(backupDir, req.Archive)
		if rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
			fatalIf(fmt.Errorf("pending restore archive is outside the protected backup directory"))
		}
		fmt.Printf("Applying verified pending restore requested by %s: %s\n", req.RequestedBy, req.Archive)
		fatalIf(dr.RestoreDataOnly(req.Archive, c.Storage.DataDir, true))
		_ = os.Remove(adminops.PendingRestorePath(c.Storage.DataDir))
		c, err = config.Load(*cp)
		fatalIf(err)
		fatalIf(secrets.Apply(&c))
	} else if !os.IsNotExist(re) {
		fatalIf(fmt.Errorf("pending restore: %w", re))
	}
	c.Storage.RetentionDays = storage.LoadRetentionOverride(c.Storage.DataDir, c.Storage.RetentionDays)
	if c.Web.TLS {
		fatalIf(validateTLSMaterial(c.Web.CertFile, c.Web.KeyFile))
	}
	fatalIf(ensureDataDirAccess(c.Storage.DataDir))
	c.Node.ID, err = ensureNodeID(c.Storage.DataDir, c.Node.ID)
	fatalIf(err)
	p, err := policy.New(filepath.Join(c.Storage.DataDir, "policies.json"), c.Security.DefaultPolicy)
	fatalIf(err)
	var st storage.Backend
	if c.Storage.Backend == "clickhouse" {
		st, err = storage.NewClickHouse(storage.ClickHouseConfig{
			URL: c.Storage.ClickHouseURL, Database: c.Storage.ClickHouseDatabase, Table: c.Storage.ClickHouseTable,
			User: c.Storage.ClickHouseUser, Password: c.Storage.ClickHousePassword, DataDir: c.Storage.DataDir, RetentionDays: c.Storage.RetentionDays,
			BatchSize: c.Storage.ClickHouseBatchSize, FlushMS: c.Storage.ClickHouseFlushMS, QueueSize: c.Storage.ClickHouseQueueSize,
			Cluster: c.Storage.ClickHouseCluster, DistributedTable: c.Storage.ClickHouseDistributedTable, ReplicaPath: c.Storage.ClickHouseReplicaPath, ReplicaName: c.Storage.ClickHouseReplicaName,
			SpoolEnabled: c.Storage.ClickHouseSpoolEnabled, SpoolMaxBytes: c.Storage.ClickHouseSpoolMaxBytes, SpoolReplaySeconds: c.Storage.ClickHouseSpoolReplaySecs, StoragePolicy: c.Storage.ClickHouseStoragePolicy, ColdVolume: c.Storage.ClickHouseColdVolume, ColdAfterDays: c.Storage.ClickHouseColdAfterDays,
			SpoolSegmentBytes: c.Storage.ClickHouseSpoolSegmentBytes, SpoolFsync: c.Storage.ClickHouseSpoolFsync, QueryTimeoutMS: c.Storage.ClickHouseQueryTimeoutMS, MaxResultRows: c.Storage.ClickHouseMaxResultRows, MaxExecutionSeconds: c.Storage.ClickHouseMaxExecutionSecs,
		})
	} else {
		st, err = storage.NewLocal(c.Storage.DataDir, 32768, c.Storage.RetentionDays)
	}
	fatalIf(err)
	defer st.Close()
	an := analytics.New()
	fatalIf(an.ConfigureRules(filepath.Join(c.Storage.DataDir, "alert-rules.json")))
	an.ConfigureBaseline(c.Analytics.BaselineEnabled, c.Analytics.BaselineMinSamples)
	an.ConfigureStateLimits(c.Analytics.MaxTrackedHosts, c.Analytics.MaxDimensionKeys)
	if c.Analytics.BaselineEnabled {
		fatalIf(an.LoadBaseline(c.Analytics.BaselineStateFile))
		baselineStop := make(chan struct{})
		baselineDone := make(chan struct{})
		go func() {
			defer close(baselineDone)
			t := time.NewTicker(time.Duration(c.Analytics.BaselineSaveSeconds) * time.Second)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					if err := an.SaveBaseline(c.Analytics.BaselineStateFile); err != nil {
						log.Printf("baseline persistence error: %v", err)
					}
				case <-baselineStop:
					return
				}
			}
		}()
		defer func() {
			close(baselineStop)
			<-baselineDone
			if err := an.SaveBaseline(c.Analytics.BaselineStateFile); err != nil {
				log.Printf("final baseline persistence error: %v", err)
			}
		}()
	}
	en, err := enrichment.NewWithRemote(c.Storage.DataDir, c.Enrichment.Enabled, c.Enrichment.PrefixFile, c.Enrichment.RemoteEnabled, c.Enrichment.RemoteURL)
	fatalIf(err)
	nm := notification.New(notification.Config{WebhookURL: c.Notifications.WebhookURL, WebhookSecret: c.Notifications.WebhookSecret, TelegramBotToken: c.Notifications.TelegramBotToken, TelegramChatID: c.Notifications.TelegramChatID, SMTPAddr: c.Notifications.SMTPAddr, SMTPFrom: c.Notifications.SMTPFrom, SMTPTo: c.Notifications.SMTPTo, SMTPUsername: c.Notifications.SMTPUsername, SMTPPassword: c.Notifications.SMTPPassword, SyslogAddr: c.Notifications.SyslogAddr})
	defer nm.Close()
	an.SetAlertSink(nm.Notify)
	au := audit.New(c.Storage.DataDir)
	ws, err := workspace.New(c.Storage.DataDir)
	fatalIf(err)
	reports, err := reporting.New(c.Storage.DataDir, st)
	fatalIf(err)
	reports.SetDelivery(func(ctx context.Context, j reporting.Job, path string, data []byte) error {
		return nm.SendReportWithEmail(ctx, j.Name, path, data, j.EmailEnabled, j.EmailRecipients)
	})
	am, bootstrap, err := auth.New(c.Storage.DataDir, c.Security.BootstrapFile, time.Duration(c.Security.SessionHours)*time.Hour)
	fatalIf(err)
	col := collector.New(c, p, st, an, en)
	fatalIf(col.Start())
	defer col.Stop()
	clusterToken, tokenErr := readOptionalSecret(c.Cluster.SharedTokenFile)
	if tokenErr != nil && c.Cluster.HeartbeatURL != "" {
		fatalIf(tokenErr)
	}
	reg, err := cluster.NewRegistry(filepath.Join(c.Storage.DataDir, "cluster-nodes.json"), clusterToken, time.Duration(c.Cluster.NodeTimeoutSeconds)*time.Second)
	fatalIf(err)
	reg.ConfigureTopology(c.Cluster.ExpectedNodes)
	clusterPrimaryToken := cluster.PrimaryToken(clusterToken)
	clusterHTTPClient := func(timeout time.Duration) *http.Client {
		if c.Cluster.RequireMTLS {
			cl, e := cluster.NewMTLSHTTPClient(c.Cluster.CAFile, c.Cluster.CertFile, c.Cluster.KeyFile, c.Cluster.ServerName, timeout)
			fatalIf(e)
			return cl
		}
		return &http.Client{Timeout: timeout}
	}
	if c.Cluster.GlobalDedupEnabled {
		reg.ConfigureDedup(time.Duration(c.Analytics.DedupWindowSeconds)*time.Second, c.Cluster.GlobalDedupMaxEntries)
		if clusterToken == "" {
			fatalIf(fmt.Errorf("global dedup enabled but cluster shared token is unavailable"))
		}
		if strings.TrimSpace(c.Cluster.GlobalDedupURL) == "" {
			col.SetGlobalDedup(func(f model.Flow) (bool, error) {
				return reg.AcceptFingerprint(dedup.FingerprintHex(f), time.Now().UTC()), nil
			})
		} else {
			dc := cluster.Client{URL: c.Cluster.GlobalDedupURL, Token: clusterPrimaryToken, HTTP: clusterHTTPClient(time.Duration(c.Cluster.GlobalDedupTimeoutMS) * time.Millisecond)}
			col.SetGlobalDedup(func(f model.Flow) (bool, error) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Cluster.GlobalDedupTimeoutMS)*time.Millisecond)
				defer cancel()
				return dc.CheckDedup(ctx, dedup.FingerprintHex(f))
			})
		}
	}
	adminMgr, err := adminops.New(*cp, c)
	fatalIf(err)
	var notificationPlatform *notification.Platform
	var notificationErr error
	// Scheduled reports must use the effective notification configuration, not
	// the startup snapshot. This makes SMTP/webhook changes in Settings take
	// effect for the next Run now / scheduled execution without a restart.
	reports.SetDelivery(func(ctx context.Context, j reporting.Job, path string, data []byte) error {
		effective := adminMgr.EffectiveConfig()
		nc := notification.Config{
			WebhookURL: effective.Notifications.WebhookURL, WebhookSecret: effective.Notifications.WebhookSecret,
			SMTPAddr: effective.Notifications.SMTPAddr, SMTPFrom: effective.Notifications.SMTPFrom, SMTPTo: effective.Notifications.SMTPTo,
			SMTPUsername: effective.Notifications.SMTPUsername, SMTPPassword: effective.Notifications.SMTPPassword,
		}
		wantsEmail := j.EmailEnabled == nil || *j.EmailEnabled
		// Keep webhook delivery independent from email transport selection.
		noEmail := false
		webhookErr := notification.SendReportConfig(ctx, nc, j.Name, path, data, &noEmail, nil)
		var emailErr error
		if wantsEmail {
			handled := false
			if notificationPlatform != nil {
				handled, emailErr = notificationPlatform.SendReportEmail(ctx, j.Name, path, data, j.EmailRecipients)
			}
			if !handled {
				yes := true
				emailErr = notification.SendReportConfig(ctx, notification.Config{
					SMTPAddr: nc.SMTPAddr, SMTPFrom: nc.SMTPFrom, SMTPTo: nc.SMTPTo, SMTPUsername: nc.SMTPUsername, SMTPPassword: nc.SMTPPassword,
				}, j.Name, path, data, &yes, j.EmailRecipients)
			}
		}
		if webhookErr != nil && emailErr != nil {
			return fmt.Errorf("%v; %v", webhookErr, emailErr)
		}
		if webhookErr != nil {
			return webhookErr
		}
		return emailErr
	})
	reports.Start()
	defer reports.Close()
	fleetRestart := make(chan struct{}, 1)
	srv := api.New(am, p, col, st, an, au, en, ws)
	routingProvider, routingErr := engineering.LoadRoutes(filepath.Join(c.Storage.DataDir, "routing-prefixes.json"))
	if routingErr != nil {
		log.Printf("routing context unavailable: %v", routingErr)
		routingProvider = engineering.NewRouteProvider()
	}
	srv.EngineeringRoutes = routingProvider
	srv.EngineeringRoutesPath = filepath.Join(c.Storage.DataDir, "routing-prefixes.json")
	notificationPlatform, notificationErr = notification.OpenPlatform(c.Storage.DataDir, srv.EvaluateNotificationRule)
	if notificationErr != nil {
		log.Printf("notification subsystem degraded: protected state unavailable")
	} else {
		srv.Notifications = notificationPlatform
		if err := nm.AdoptPlatform(notificationPlatform); err != nil {
			log.Printf("notification legacy profile migration failed; existing adapter remains active")
		}
		notificationPlatform.Start()
		defer notificationPlatform.Close()
	}

	srv.SetAdminOps(adminMgr)
	srv.SetRestart(func() {
		select {
		case fleetRestart <- struct{}{}:
		default:
		}
	})
	srv.SetCluster(reg)
	srv.SetReports(reports)
	srv.SetNodeInfo(c.Node.ID, c.Node.Region)
	srv.SetRequireMFA(c.Security.RequireMFA)
	srv.SetDiagnosticsEnabled(c.Security.DiagnosticsEnabled)
	srv.SetClusterRequireMTLS(c.Cluster.RequireMTLS)
	if c.OIDC.Enabled {
		octx, ocancel := context.WithTimeout(context.Background(), 12*time.Second)
		om, oe := oidcauth.New(octx, oidcauth.Config{Issuer: c.OIDC.Issuer, ClientID: c.OIDC.ClientID, ClientSecret: c.OIDC.ClientSecret, RedirectURL: c.OIDC.RedirectURL, DefaultRole: c.OIDC.DefaultRole, GroupRoleMap: c.OIDC.GroupRoleMap})
		ocancel()
		fatalIf(oe)
		srv.SetOIDC(om)
	}
	if c.LDAP.Enabled {
		lm, le := ldapauth.New(ldapauth.Config{URL: c.LDAP.URL, BindDN: c.LDAP.BindDN, BindPassword: c.LDAP.BindPassword, BaseDN: c.LDAP.BaseDN, UserAttribute: c.LDAP.UserAttribute, UserDNTemplate: c.LDAP.UserDNTemplate, GroupAttribute: c.LDAP.GroupAttribute, GroupRoleMap: c.LDAP.GroupRoleMap, DefaultRole: c.LDAP.DefaultRole, AllowInsecure: c.LDAP.AllowInsecure})
		fatalIf(le)
		srv.SetLDAP(lm)
	}
	if c.Cluster.HeartbeatURL != "" {
		if clusterToken == "" {
			fatalIf(fmt.Errorf("cluster heartbeat configured but shared token file %s is empty or missing", c.Cluster.SharedTokenFile))
		}
		stopHB := make(chan struct{})
		doneHB := make(chan struct{})
		startedAt := time.Now().UTC()
		client := cluster.Client{URL: c.Cluster.HeartbeatURL, Token: clusterPrimaryToken, Interval: time.Duration(c.Cluster.HeartbeatSeconds) * time.Second, HTTP: clusterHTTPClient(8 * time.Second)}
		go func() {
			defer close(doneHB)
			ticker := time.NewTicker(time.Duration(c.Cluster.HeartbeatSeconds) * time.Second)
			defer ticker.Stop()
			post := func(h cluster.Heartbeat) (cluster.HeartbeatResponse, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				return client.SendWithDirective(ctx, h)
			}
			base := func() cluster.Heartbeat {
				ss := st.Stats()
				ds := col.DedupStats()
				return cluster.Heartbeat{NodeID: c.Node.ID, Region: c.Node.Region, Version: buildinfo.Version, StartedAt: startedAt, StorageBackend: ss.Backend, Healthy: ss.Healthy, ConfigVersion: buildinfo.Version, Metrics: map[string]any{"storage_queue_depth": ss.QueueDepth, "storage_dropped": ss.Dropped, "dedup_duplicates": ds.Duplicates, "exporters": len(col.Exporters())}}
			}
			send := func() {
				h := base()
				resp, err := post(h)
				if err != nil {
					log.Printf("cluster heartbeat error: %v", err)
					return
				}
				if resp.Command == nil {
					return
				}
				cmd := resp.Command
				status := "ok"
				switch cmd.Action {
				case "reload_policies":
					if err := p.Reload(); err != nil {
						status = "error: " + err.Error()
					}
				case "restart_service":
					status = "accepted"
				case "diagnostics":
					ss := st.Stats()
					ds := col.DedupStats()
					status = fmt.Sprintf("ok storage=%s healthy=%v queue=%d dropped=%d dedup_duplicates=%d exporters=%d goroutines=%d", ss.Backend, ss.Healthy, ss.QueueDepth, ss.Dropped, ds.Duplicates, len(col.Exporters()), runtime.NumGoroutine())
				default:
					status = "error: unsupported action"
				}
				ack := base()
				ack.LastCommandID = cmd.ID
				ack.LastCommandStatus = status
				if _, err := post(ack); err != nil {
					log.Printf("cluster command acknowledgment error: %v", err)
				}
				if cmd.Action == "restart_service" && status == "accepted" {
					select {
					case fleetRestart <- struct{}{}:
					default:
					}
				}
			}
			send()
			for {
				select {
				case <-ticker.C:
					send()
				case <-stopHB:
					return
				}
			}
		}()
		defer func() { close(stopHB); <-doneHB }()
	}
	hs := &http.Server{Addr: fmt.Sprintf("%s:%d", c.Web.Bind, c.Web.Port), Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
	if c.Cluster.RequireMTLS {
		caPEM, e := os.ReadFile(c.Cluster.CAFile)
		fatalIf(e)
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			fatalIf(fmt.Errorf("cluster CA file contains no certificates"))
		}
		hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven}
	}
	fmt.Println("\nCentral Flow Collector")
	scheme := "http"
	if c.Web.TLS {
		scheme = "https"
	}
	fmt.Printf("Version: %s (%s)\nNode: %s region=%s\nConfig: %s\nWeb UI: %s://%s:%d\nStorage: %s\nPolicy: DEFAULT %s\nEnrichment: enabled=%v prefixes=%d sites=%d\nTraffic baseline: enabled=%v min_samples=%d state=%s\n", buildinfo.Version, buildinfo.Commit, c.Node.ID, c.Node.Region, *cp, scheme, displayHost(c.Web.Bind), c.Web.Port, storageDescription(c), strings.ToUpper(c.Security.DefaultPolicy), en.Status().Enabled, en.Status().Prefixes, en.Status().Sites, c.Analytics.BaselineEnabled, c.Analytics.BaselineMinSamples, c.Analytics.BaselineStateFile)
	if c.Web.TLS {
		fmt.Printf("Web transport: HTTPS using explicit certificate %s\n", c.Web.CertFile)
	} else {
		fmt.Println("Web transport: HTTP (TLS disabled; no certificate negotiation or browser certificate warnings)")
		if !isLoopbackBind(c.Web.Bind) {
			log.Printf("SECURITY WARNING: web UI is using plaintext HTTP on non-loopback bind %q; use a trusted TLS certificate or a TLS reverse proxy for untrusted networks", c.Web.Bind)
		}
	}
	for _, l := range c.Listeners {
		if l.Enabled {
			fmt.Printf("Listener: %-10s %s:%d/UDP ACTIVE\n", strings.ToUpper(l.Protocol), l.Bind, l.Port)
		}
	}
	if bootstrap != "" {
		fmt.Printf("Bootstrap admin created. Temporary credential stored securely at: %s\n", c.Security.BootstrapFile)
	}
	fmt.Println()
	errch := make(chan error, 1)
	go func() {
		if c.Web.TLS {
			errch <- hs.ListenAndServeTLS(c.Web.CertFile, c.Web.KeyFile)
		} else {
			errch <- hs.ListenAndServe()
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	exitCode := 0
	select {
	case s := <-sig:
		log.Printf("shutdown signal: %s", s)
	case <-fleetRestart:
		log.Printf("fleet command requested graceful service restart")
		// systemd unit uses Restart=on-failure. 75 is reserved here for a
		// controller-requested restart after all normal shutdown/defer cleanup.
		exitCode = 75
	case e := <-errch:
		if e != nil && e != http.ErrServerClosed {
			log.Printf("server error: %v", e)
			exitCode = 1
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = hs.Shutdown(ctx)
	col.Stop()
	return exitCode
}
func configCmd(args []string) {
	if len(args) < 1 || args[0] != "validate" {
		usage()
		os.Exit(2)
	}
	fs := flag.NewFlagSet("config validate", flag.ExitOnError)
	cp := cfgFlag(fs)
	_ = fs.Parse(args[1:])
	c, e := config.Load(*cp)
	if e == nil {
		e = secrets.Apply(&c)
	}
	if e == nil && c.Web.TLS {
		e = validateTLSMaterial(c.Web.CertFile, c.Web.KeyFile)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "INVALID:", e)
		os.Exit(1)
	}
	fmt.Printf("VALID: %s (%d listeners, storage=%s, default_policy=%s, web_tls=%v)\n", *cp, len(c.Listeners), c.Storage.Backend, c.Security.DefaultPolicy, c.Web.TLS)
}
func userCmd(args []string) {
	if len(args) < 1 || args[0] != "reset-password" {
		usage()
		os.Exit(2)
	}
	fs := flag.NewFlagSet("user reset-password", flag.ExitOnError)
	cp := cfgFlag(fs)
	user := fs.String("username", "admin", "username")
	pw := fs.String("password", "", "new password (omit to read one line from stdin)")
	_ = fs.Parse(args[1:])
	c, e := config.Load(*cp)
	fatalIf(e)
	if *pw == "" {
		fmt.Print("New password: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		*pw = strings.TrimSpace(line)
	}
	am, _, e := auth.New(c.Storage.DataDir, c.Security.BootstrapFile, time.Duration(c.Security.SessionHours)*time.Hour)
	fatalIf(e)
	fatalIf(am.ResetPassword(*user, *pw))
	fmt.Printf("Password reset for %s. Existing sessions invalidated.\n", *user)
}
func policyCmd(args []string) {
	if len(args) < 1 || args[0] != "test" {
		usage()
		os.Exit(2)
	}
	fs := flag.NewFlagSet("policy test", flag.ExitOnError)
	cp := cfgFlag(fs)
	src := fs.String("source", "", "source IP")
	proto := fs.String("protocol", "netflow", "protocol")
	listener := fs.String("listener", "netflow", "listener")
	port := fs.Int("port", 2055, "destination port")
	_ = fs.Parse(args[1:])
	c, e := config.Load(*cp)
	fatalIf(e)
	p, e := policy.New(filepath.Join(c.Storage.DataDir, "policies.json"), c.Security.DefaultPolicy)
	fatalIf(e)
	d := p.Decide(*src, *proto, *listener, *port)
	fmt.Printf("allowed=%v rule=%s reason=%s\n", d.Allowed, d.RuleID, d.Reason)
}

func auditCmd(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	sub := args[0]
	fs := flag.NewFlagSet("audit "+sub, flag.ExitOnError)
	cp := cfgFlag(fs)
	out := fs.String("output", "", "export path")
	_ = fs.Parse(args[1:])
	c, e := config.Load(*cp)
	fatalIf(e)
	l := audit.New(c.Storage.DataDir)
	switch sub {
	case "verify":
		v := l.Verify()
		fmt.Printf("ok=%v records=%d verified=%d legacy=%d first_broken=%d error=%s\n", v.OK, v.Records, v.Verified, v.Legacy, v.FirstBroken, v.Error)
		if !v.OK {
			os.Exit(1)
		}
	case "export":
		if *out == "" {
			fatalIf(fmt.Errorf("--output is required"))
		}
		fatalIf(l.Export(*out))
		fmt.Printf("Audit log exported to %s\n", *out)
	default:
		usage()
		os.Exit(2)
	}
}
func diagnostics(args []string) {
	fs := flag.NewFlagSet("diagnostics", flag.ExitOnError)
	cp := cfgFlag(fs)
	_ = fs.Parse(args)
	c, e := config.Load(*cp)
	fatalIf(e)
	fmt.Printf("config=OK\ndata_dir=%s\npolicy_file=%s\nweb=%s:%d tls=%v\nstorage=%s\nenrichment_enabled=%v\nenrichment_prefix_file=%s\n", c.Storage.DataDir, filepath.Join(c.Storage.DataDir, "policies.json"), c.Web.Bind, c.Web.Port, c.Web.TLS, storageDescription(c), c.Enrichment.Enabled, c.Enrichment.PrefixFile)
	for _, l := range c.Listeners {
		fmt.Printf("listener=%s bind=%s:%d protocol=%s enabled=%v workers=%d queue=%d\n", l.Name, l.Bind, l.Port, l.Protocol, l.Enabled, l.Workers, l.QueueSize)
	}
}
func healthCmd(args []string) {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	u := fs.String("url", "http://127.0.0.1:8080/health", "health URL")
	_ = fs.Parse(args)
	cl := &http.Client{Timeout: 4 * time.Second}
	resp, e := cl.Get(*u)
	fatalIf(e)
	defer resp.Body.Close()
	fmt.Printf("HTTP %s\n", resp.Status)
	if resp.StatusCode/100 != 2 {
		os.Exit(1)
	}
}

func migrateCmd(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	cp := cfgFlag(fs)
	_ = fs.Parse(args)
	c, err := config.Load(*cp)
	fatalIf(err)
	// A portal-scheduled metadata restore is executed before any stateful
	// subsystem opens files or listeners. The request can only reference an
	// archive inside the protected data-dir backup directory.
	if req, re := adminops.LoadPendingRestore(c.Storage.DataDir); re == nil {
		backupDir := filepath.Join(c.Storage.DataDir, "backups")
		rel, rerr := filepath.Rel(backupDir, req.Archive)
		if rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
			fatalIf(fmt.Errorf("pending restore archive is outside the protected backup directory"))
		}
		fmt.Printf("Applying verified pending restore requested by %s: %s\n", req.RequestedBy, req.Archive)
		fatalIf(dr.RestoreDataOnly(req.Archive, c.Storage.DataDir, true))
		_ = os.Remove(adminops.PendingRestorePath(c.Storage.DataDir))
		c, err = config.Load(*cp)
		fatalIf(err)
	} else if !os.IsNotExist(re) {
		fatalIf(fmt.Errorf("pending restore: %w", re))
	}
	c.Storage.RetentionDays = storage.LoadRetentionOverride(c.Storage.DataDir, c.Storage.RetentionDays)
	if c.Storage.Backend != "clickhouse" {
		fmt.Println("Local storage uses append-only JSONL and atomic metadata; no schema migration is required.")
		return
	}
	st, err := storage.NewClickHouse(storage.ClickHouseConfig{
		URL: c.Storage.ClickHouseURL, Database: c.Storage.ClickHouseDatabase, Table: c.Storage.ClickHouseTable,
		User: c.Storage.ClickHouseUser, Password: c.Storage.ClickHousePassword, DataDir: c.Storage.DataDir, RetentionDays: c.Storage.RetentionDays,
		BatchSize: c.Storage.ClickHouseBatchSize, FlushMS: c.Storage.ClickHouseFlushMS, QueueSize: c.Storage.ClickHouseQueueSize,
		Cluster: c.Storage.ClickHouseCluster, DistributedTable: c.Storage.ClickHouseDistributedTable, ReplicaPath: c.Storage.ClickHouseReplicaPath, ReplicaName: c.Storage.ClickHouseReplicaName,
		SpoolEnabled: c.Storage.ClickHouseSpoolEnabled, SpoolMaxBytes: c.Storage.ClickHouseSpoolMaxBytes, SpoolReplaySeconds: c.Storage.ClickHouseSpoolReplaySecs, StoragePolicy: c.Storage.ClickHouseStoragePolicy, ColdVolume: c.Storage.ClickHouseColdVolume, ColdAfterDays: c.Storage.ClickHouseColdAfterDays,
	})
	fatalIf(err)
	fatalIf(st.Close())
	fmt.Printf("ClickHouse schema ready: %s/%s.%s retention=%dd\n", c.Storage.ClickHouseURL, c.Storage.ClickHouseDatabase, c.Storage.ClickHouseTable, c.Storage.RetentionDays)
}

func backupCmd(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("backup create", flag.ExitOnError)
		cp := cfgFlag(fs)
		out := fs.String("output", "", "backup archive path")
		includeFlows := fs.Bool("include-flows", false, "include raw local flow files (can be large)")
		_ = fs.Parse(args[1:])
		c, e := config.Load(*cp)
		fatalIf(e)
		if *out == "" {
			fatalIf(fmt.Errorf("--output is required"))
		}
		m, e := dr.Create(*cp, c.Storage.DataDir, *out, *includeFlows)
		fatalIf(e)
		fmt.Printf("Backup created: %s\nentries=%d include_flows=%v created_at=%s\n", *out, len(m.Entries), m.IncludesFlows, m.CreatedAt.Format(time.RFC3339))
	case "verify":
		fs := flag.NewFlagSet("backup verify", flag.ExitOnError)
		arc := fs.String("archive", "", "backup archive path")
		_ = fs.Parse(args[1:])
		if *arc == "" {
			fatalIf(fmt.Errorf("--archive is required"))
		}
		r, e := dr.Verify(*arc)
		fatalIf(e)
		fmt.Printf("VALID backup: entries=%d include_flows=%v created_at=%s\n", r.Entries, r.IncludesFlows, r.CreatedAt.Format(time.RFC3339))
	default:
		usage()
		os.Exit(2)
	}
}
func restoreCmd(args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	cp := cfgFlag(fs)
	arc := fs.String("archive", "", "backup archive path")
	force := fs.Bool("force", false, "confirm destructive metadata restore")
	_ = fs.Parse(args)
	c, e := config.Load(*cp)
	fatalIf(e)
	if *arc == "" {
		fatalIf(fmt.Errorf("--archive is required"))
	}
	fatalIf(dr.Restore(*arc, *cp, c.Storage.DataDir, *force))
	fmt.Println("Restore complete. Restart flowcollector and run 'flowcollector repair check --config', then verify /ready before resuming ingestion.")
}
func repairCmd(args []string) {
	if len(args) < 1 || args[0] != "check" {
		usage()
		os.Exit(2)
	}
	fs := flag.NewFlagSet("repair check", flag.ExitOnError)
	cp := cfgFlag(fs)
	_ = fs.Parse(args[1:])
	c, e := config.Load(*cp)
	fatalIf(e)
	r := dr.Check(c.Storage.DataDir)
	fmt.Printf("data_dir=%s healthy=%v\n", r.DataDir, r.Healthy)
	for _, x := range r.Items {
		fmt.Printf("%s exists=%v readable=%v writable=%v", x.Path, x.Exists, x.Readable, x.Writable)
		if x.JSONValid != nil {
			fmt.Printf(" json_valid=%v", *x.JSONValid)
		}
		if x.Error != "" {
			fmt.Printf(" error=%q", x.Error)
		}
		fmt.Println()
	}
	if !r.Healthy {
		os.Exit(1)
	}
}

func clickhouseBackupCmd(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	parseRFC := func(raw string) time.Time {
		if strings.TrimSpace(raw) == "" {
			return time.Time{}
		}
		t, e := time.Parse(time.RFC3339, raw)
		fatalIf(e)
		return t
	}
	openCH := func(cp string) (*storage.ClickHouse, config.Config) {
		c, e := config.Load(cp)
		fatalIf(e)
		if c.Storage.Backend != "clickhouse" {
			fatalIf(fmt.Errorf("storage.backend must be clickhouse for this command"))
		}
		c.Storage.RetentionDays = storage.LoadRetentionOverride(c.Storage.DataDir, c.Storage.RetentionDays)
		st, e := storage.NewClickHouse(storage.ClickHouseConfig{URL: c.Storage.ClickHouseURL, Database: c.Storage.ClickHouseDatabase, Table: c.Storage.ClickHouseTable, User: c.Storage.ClickHouseUser, Password: c.Storage.ClickHousePassword, DataDir: c.Storage.DataDir, RetentionDays: c.Storage.RetentionDays, BatchSize: c.Storage.ClickHouseBatchSize, FlushMS: c.Storage.ClickHouseFlushMS, QueueSize: c.Storage.ClickHouseQueueSize, Cluster: c.Storage.ClickHouseCluster, DistributedTable: c.Storage.ClickHouseDistributedTable, ReplicaPath: c.Storage.ClickHouseReplicaPath, ReplicaName: c.Storage.ClickHouseReplicaName, SpoolEnabled: c.Storage.ClickHouseSpoolEnabled, SpoolMaxBytes: c.Storage.ClickHouseSpoolMaxBytes, SpoolReplaySeconds: c.Storage.ClickHouseSpoolReplaySecs})
		fatalIf(e)
		return st, c
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("clickhouse-backup create", flag.ExitOnError)
		cp := cfgFlag(fs)
		out := fs.String("output", "", "gzip JSONEachRow backup path")
		from := fs.String("from", "", "optional RFC3339 start")
		to := fs.String("to", "", "optional RFC3339 end")
		_ = fs.Parse(args[1:])
		if *out == "" {
			fatalIf(fmt.Errorf("--output is required"))
		}
		st, _ := openCH(*cp)
		defer st.Close()
		m, e := st.LogicalBackup(context.Background(), *out, parseRFC(*from), parseRFC(*to))
		fatalIf(e)
		fmt.Printf("ClickHouse logical backup created: %s\nrows=%d sha256=%s manifest=%s.manifest.json\n", *out, m.Rows, m.SHA256, *out)
	case "verify":
		fs := flag.NewFlagSet("clickhouse-backup verify", flag.ExitOnError)
		arc := fs.String("archive", "", "backup path")
		_ = fs.Parse(args[1:])
		if *arc == "" {
			fatalIf(fmt.Errorf("--archive is required"))
		}
		m, e := storage.VerifyClickHouseBackup(*arc)
		fatalIf(e)
		fmt.Printf("VALID ClickHouse logical backup: rows=%d sha256=%s created_at=%s\n", m.Rows, m.SHA256, m.CreatedAt.Format(time.RFC3339))
	case "restore":
		fs := flag.NewFlagSet("clickhouse-backup restore", flag.ExitOnError)
		cp := cfgFlag(fs)
		arc := fs.String("archive", "", "backup path")
		force := fs.Bool("force", false, "confirm logical flow restore")
		_ = fs.Parse(args[1:])
		if *arc == "" {
			fatalIf(fmt.Errorf("--archive is required"))
		}
		st, _ := openCH(*cp)
		defer st.Close()
		m, e := st.LogicalRestore(context.Background(), *arc, *force)
		fatalIf(e)
		fmt.Printf("ClickHouse logical restore complete: rows_expected=%d source_created_at=%s\n", m.Rows, m.CreatedAt.Format(time.RFC3339))
	default:
		usage()
		os.Exit(2)
	}
}

func storageDescription(c config.Config) string {
	if c.Storage.Backend == "clickhouse" {
		u, err := url.Parse(c.Storage.ClickHouseURL)
		safeURL := c.Storage.ClickHouseURL
		if err == nil {
			if u.User != nil {
				u.User = url.User("REDACTED")
			}
			safeURL = u.String()
		}
		return fmt.Sprintf("clickhouse (%s/%s.%s)", safeURL, c.Storage.ClickHouseDatabase, c.Storage.ClickHouseTable)
	}
	return fmt.Sprintf("local (%s)", c.Storage.DataDir)
}

func ensureDataDirAccess(dir string) error {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create data directory %s: %w", dir, err)
	}
	probe := filepath.Join(dir, fmt.Sprintf(".write-probe-%d", os.Getpid()))
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("data directory %s is not writable by uid=%d gid=%d: %w; if this is a systemd installation, rerun install.sh v1.2.0 to repair ownership", dir, os.Geteuid(), os.Getegid(), err)
	}
	_ = f.Close()
	_ = os.Remove(probe)

	for _, name := range []string{"users.json", "policies.json", "audit.jsonl"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("inspect persistent state %s: %w", p, err)
		}
		f, err := os.OpenFile(p, os.O_RDWR, 0)
		if err != nil {
			return fmt.Errorf("persistent state file %s is not readable/writable by uid=%d gid=%d: %w; rerun install.sh v1.2.0 to repair ownership", p, os.Geteuid(), os.Getegid(), err)
		}
		_ = f.Close()
	}
	return nil
}
func validateTLSMaterial(certPath, keyPath string) error {
	if strings.TrimSpace(certPath) == "" || strings.TrimSpace(keyPath) == "" {
		return fmt.Errorf("HTTPS requires explicit cert_file and key_file; automatic self-signed certificates are disabled")
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("invalid TLS certificate/key pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return fmt.Errorf("TLS certificate file contains no certificates")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse TLS certificate: %w", err)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("TLS certificate is not valid before %s", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("TLS certificate expired at %s", cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

func isLoopbackBind(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func readOptionalSecret(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read secret file %s: %w", path, err)
	}
	if len(b) > 16*1024 {
		return "", fmt.Errorf("secret file %s is unexpectedly large", path)
	}
	return strings.TrimSpace(string(b)), nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func displayHost(h string) string {
	if h == "0.0.0.0" || h == "::" || h == "" {
		return "127.0.0.1"
	}
	return h
}
func ensureNodeID(dataDir, configured string) (string, error) {
	if strings.TrimSpace(configured) != "" {
		return strings.TrimSpace(configured), nil
	}
	p := filepath.Join(dataDir, "node-id")
	if b, err := os.ReadFile(p); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return v, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	host, _ := os.Hostname()
	host = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r) {
			return r
		}
		return '-'
	}, host)
	if host == "" {
		host = "collector"
	}
	if len(host) > 48 {
		host = host[:48]
	}
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := host + "-" + hex.EncodeToString(b)
	if err := os.WriteFile(p, []byte(id+"\n"), 0640); err != nil {
		return "", err
	}
	return id, nil
}

func fatalIf(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", e)
		os.Exit(1)
	}
}
