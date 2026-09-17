package api

import "central-flow-collector/internal/audit"

func (s *Server) writeCompatAudit(x auditEventCompat) {
	if s.Audit != nil {
		s.Audit.Write(audit.Event{User: x.User, Action: x.Action, Source: x.Source, Success: x.Success, Detail: x.Detail})
	}
}
