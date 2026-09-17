package api

import (
	"central-flow-collector/internal/audit"
	"central-flow-collector/internal/auth"
	"central-flow-collector/internal/reporting"
	"context"
	"net"
	"net/http"
	"time"
)

func requestRP(r *http.Request) (string, string) {
	h := r.Host
	if host, _, e := net.SplitHostPort(h); e == nil {
		h = host
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return h, scheme + "://" + r.Host
}
func setSessionCookie(w http.ResponseWriter, r *http.Request, s auth.Session) {
	http.SetCookie(w, &http.Cookie{Name: "fc_session", Value: s.ID, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, Expires: s.Expires})
}
func (s *Server) ldapStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]bool{"enabled": s.LDAP != nil})
}
func (s *Server) ldapLogin(w http.ResponseWriter, r *http.Request) {
	if s.LDAP == nil {
		writeErr(w, 404, "LDAP is not configured")
		return
	}
	var in struct{ Username, Password string }
	if !decode(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	id, e := s.LDAP.Authenticate(ctx, in.Username, in.Password)
	if e != nil {
		s.Audit.Write(audit.Event{User: in.Username, Action: "ldap_login_failure", Source: remoteIP(r), Success: false, Detail: e.Error()})
		writeErr(w, 401, "LDAP authentication failed")
		return
	}
	sess, e := s.Auth.CreateExternalSessionScoped(id.Username, id.Role, "", "ldap")
	if e != nil {
		writeErr(w, 403, e.Error())
		return
	}
	setSessionCookie(w, r, sess)
	s.Audit.Write(audit.Event{User: id.Username, Action: "ldap_login", Source: remoteIP(r), Success: true, Detail: "dn=" + id.DN})
	writeJSON(w, 200, map[string]any{"csrf": sess.CSRF, "user": map[string]any{"username": id.Username, "role": id.Role}, "groups": id.Groups})
}
func (s *Server) mfaStatus(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	writeJSON(w, 200, s.Auth.MFAStatus(ss.Username))
}
func (s *Server) mfaTOTPBegin(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	secret, uri, e := s.Auth.BeginTOTP(ss.Username)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "mfa_totp_begin", Source: remoteIP(r), Success: true})
	writeJSON(w, 200, map[string]string{"secret": secret, "otpauth_uri": uri})
}
func (s *Server) mfaTOTPConfirm(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	var in struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	codes, e := s.Auth.ConfirmTOTP(ss.Username, in.Code)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "mfa_totp_enable", Source: remoteIP(r), Success: true})
	writeJSON(w, 200, map[string]any{"ok": true, "recovery_codes": codes, "warning": "Recovery codes are shown once. Store them securely."})
}
func (s *Server) mfaTOTPDisable(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	var in struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	e := s.Auth.DisableTOTP(ss.Username, in.Code)
	s.Audit.Write(audit.Event{User: ss.Username, Action: "mfa_totp_disable", Source: remoteIP(r), Success: e == nil})
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) webauthnRegisterOptions(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	rp, origin := requestRP(r)
	o, e := s.Auth.BeginWebAuthnRegistration(ss.Username, rp, origin)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, o)
}
func (s *Server) webauthnRegisterFinish(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	var in auth.WebAuthnRegistrationResponse
	if !decode(w, r, &in) {
		return
	}
	e := s.Auth.FinishWebAuthnRegistration(ss.Username, in)
	s.Audit.Write(audit.Event{User: ss.Username, Action: "passkey_register", Source: remoteIP(r), Success: e == nil})
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) webauthnAssertOptions(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
	}
	if !decode(w, r, &in) {
		return
	}
	rp, origin := requestRP(r)
	o, e := s.Auth.BeginWebAuthnAssertion(in.Username, rp, origin)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, o)
}
func (s *Server) webauthnAssertFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username  string                         `json:"username"`
		Assertion auth.WebAuthnAssertionResponse `json:"assertion"`
	}
	if !decode(w, r, &in) {
		return
	}
	sess, e := s.Auth.FinishWebAuthnAssertion(in.Username, in.Assertion)
	if e != nil {
		s.Audit.Write(audit.Event{User: in.Username, Action: "passkey_login_failure", Source: remoteIP(r), Success: false, Detail: e.Error()})
		writeErr(w, 401, "passkey authentication failed")
		return
	}
	setSessionCookie(w, r, sess)
	u, _ := s.Auth.User(in.Username)
	s.Audit.Write(audit.Event{User: in.Username, Action: "passkey_login", Source: remoteIP(r), Success: true})
	writeJSON(w, 200, map[string]any{"csrf": sess.CSRF, "user": view(u)})
}

func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	writeJSON(w, 200, s.Audit.Verify())
}
func (s *Server) reportJobs(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Reports == nil {
		writeJSON(w, 200, []reporting.Job{})
		return
	}
	writeJSON(w, 200, s.Reports.Jobs())
}
func (s *Server) reportUpsert(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Reports == nil {
		writeErr(w, 500, "reporting unavailable")
		return
	}
	var j reporting.Job
	if !decode(w, r, &j) {
		return
	}
	x, e := s.Reports.Upsert(j)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "report_upsert", Source: remoteIP(r), Object: x.ID, Success: true})
	writeJSON(w, 200, x)
}
func (s *Server) reportDelete(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Reports == nil {
		writeErr(w, 500, "reporting unavailable")
		return
	}
	id := r.PathValue("id")
	if e := s.Reports.Delete(id); e != nil {
		writeErr(w, 404, e.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "report_delete", Source: remoteIP(r), Object: id, Success: true})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) reportRun(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Reports == nil {
		writeErr(w, 500, "reporting unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	p, b, e := s.Reports.RunNow(ctx, r.PathValue("id"), time.Now())
	if e != nil {
		if e.Error() == "report not found" {
			writeErr(w, 404, e.Error())
			return
		}
		writeErr(w, 500, e.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "report_run", Source: remoteIP(r), Object: r.PathValue("id"), Success: true})
	writeJSON(w, 200, map[string]any{"path": p, "bytes": len(b)})
}
func (s *Server) clusterRollouts(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Cluster == nil {
		writeJSON(w, 200, []any{})
		return
	}
	writeJSON(w, 200, s.Cluster.Rollouts())
}
func (s *Server) clusterRolloutStart(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Cluster == nil {
		writeErr(w, 500, "cluster unavailable")
		return
	}
	var in struct {
		Name, Action string
		NodeIDs      []string `json:"node_ids"`
		Stages       []int    `json:"stages"`
	}
	if !decode(w, r, &in) {
		return
	}
	x, e := s.Cluster.StartRollout(in.Name, in.Action, ss.Username, in.NodeIDs, in.Stages)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	writeJSON(w, 201, x)
}
func (s *Server) clusterRolloutAdvance(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	x, e := s.Cluster.AdvanceRollout(r.PathValue("id"))
	if e != nil {
		writeJSON(w, 409, map[string]any{"error": e.Error(), "rollout": x})
		return
	}
	writeJSON(w, 200, x)
}
