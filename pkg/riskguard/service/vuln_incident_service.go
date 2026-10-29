package service

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"cyberspring/pkg/riskguard/models"
)

// SecurityService manages vulnerabilities, alerts, and incident response workflows.
type SecurityService struct {
	db *sql.DB
}

// NewSecurityService creates a SecurityService.
func NewSecurityService(db *sql.DB) *SecurityService {
	return &SecurityService{db: db}
}

// ListVulnerabilities returns vulnerabilities with asset and risk cross-references.
func (s *SecurityService) ListVulnerabilities(severity, status, query string) ([]models.Vulnerability, error) {
	var conditions []string
	var args []interface{}

	if severity != "" && severity != "All" {
		conditions = append(conditions, "v.severity = ?")
		args = append(args, severity)
	}
	if status != "" && status != "All" {
		conditions = append(conditions, "v.status = ?")
		args = append(args, status)
	}
	if query != "" {
		like := "%" + query + "%"
		conditions = append(conditions, "(v.cve_id LIKE ? OR v.title LIKE ? OR v.affected_software LIKE ?)")
		args = append(args, like, like, like)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	querySQL := fmt.Sprintf(`
		SELECT v.id, v.cve_id, v.title, v.description, v.severity, v.cvss_score,
		       v.affected_software, v.affected_asset_id, COALESCE(a.name, '') as asset_name,
		       v.linked_risk_id, COALESCE(r.risk_code, '') as risk_code,
		       v.remediation_guidance, v.owner, v.due_date, v.status, v.verified_at,
		       v.created_at, v.updated_at
		FROM vulnerabilities v
		LEFT JOIN assets a ON v.affected_asset_id = a.id
		LEFT JOIN risks r ON v.linked_risk_id = r.id
		%s
		ORDER BY v.cvss_score DESC, v.created_at DESC
	`, whereClause)

	rows, err := s.db.Query(querySQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.Vulnerability
	for rows.Next() {
		var v models.Vulnerability
		err := rows.Scan(
			&v.ID, &v.CVEID, &v.Title, &v.Description, &v.Severity, &v.CVSSScore,
			&v.AffectedSoftware, &v.AffectedAssetID, &v.AffectedAssetName,
			&v.LinkedRiskID, &v.LinkedRiskCode, &v.RemediationGuidance, &v.Owner,
			&v.DueDate, &v.Status, &v.VerifiedAt, &v.CreatedAt, &v.UpdatedAt,
		)
		if err == nil {
			results = append(results, v)
		}
	}
	return results, nil
}

// CreateVulnerability inserts a new vulnerability finding.
func (s *SecurityService) CreateVulnerability(v *models.Vulnerability) error {
	if v.ID == "" {
		v.ID = fmt.Sprintf("vuln_%d", time.Now().UnixNano())
	}
	if v.Status == "" {
		v.Status = "Open"
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	v.CreatedAt = now
	v.UpdatedAt = now

	_, err := s.db.Exec(`
		INSERT INTO vulnerabilities 
		(id, cve_id, title, description, severity, cvss_score, affected_software,
		 affected_asset_id, linked_risk_id, remediation_guidance, owner, due_date, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		v.ID, v.CVEID, v.Title, v.Description, v.Severity, v.CVSSScore, v.AffectedSoftware,
		v.AffectedAssetID, v.LinkedRiskID, v.RemediationGuidance, v.Owner, v.DueDate, v.Status, v.CreatedAt, v.UpdatedAt,
	)
	return err
}

// UpdateVulnerabilityStatus updates the remediation progress of a vulnerability.
func (s *SecurityService) UpdateVulnerabilityStatus(id, status string) error {
	verifiedAt := ""
	if status == "Patched" {
		verifiedAt = time.Now().Format("2006-01-02 15:04:05")
	}
	now := time.Now().Format("2006-01-02 15:04:05")

	_, err := s.db.Exec(`
		UPDATE vulnerabilities SET status = ?, verified_at = ?, updated_at = ? WHERE id = ?
	`, status, verifiedAt, now, id)
	return err
}

// ListIncidents returns active security incidents with asset linkage and timeline.
func (s *SecurityService) ListIncidents(status, query string) ([]models.Incident, error) {
	var conditions []string
	var args []interface{}

	if status != "" && status != "All" {
		conditions = append(conditions, "i.status = ?")
		args = append(args, status)
	}
	if query != "" {
		like := "%" + query + "%"
		conditions = append(conditions, "(i.incident_code LIKE ? OR i.title LIKE ? OR i.lead_investigator LIKE ?)")
		args = append(args, like, like, like)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	querySQL := fmt.Sprintf(`
		SELECT i.id, i.incident_code, i.title, i.description, i.severity, i.status,
		       i.lead_investigator, i.affected_asset_id, COALESCE(a.name, '') as asset_name,
		       i.linked_risk_id, i.root_cause, i.containment_action, i.containment_status,
		       i.resolved_at, i.created_at, i.updated_at
		FROM incidents i
		LEFT JOIN assets a ON i.affected_asset_id = a.id
		%s
		ORDER BY i.created_at DESC
	`, whereClause)

	rows, err := s.db.Query(querySQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.Incident
	for rows.Next() {
		var inc models.Incident
		err := rows.Scan(
			&inc.ID, &inc.IncidentCode, &inc.Title, &inc.Description, &inc.Severity,
			&inc.Status, &inc.LeadInvestigator, &inc.AffectedAssetID, &inc.AffectedAssetName,
			&inc.LinkedRiskID, &inc.RootCause, &inc.ContainmentAction, &inc.ContainmentStatus,
			&inc.ResolvedAt, &inc.CreatedAt, &inc.UpdatedAt,
		)
		if err == nil {
			results = append(results, inc)
		}
	}
	return results, nil
}

// CreateIncident creates a new incident.
func (s *SecurityService) CreateIncident(inc *models.Incident) error {
	if inc.ID == "" {
		inc.ID = fmt.Sprintf("inc_%d", time.Now().UnixNano())
	}
	if inc.IncidentCode == "" {
		var count int
		_ = s.db.QueryRow("SELECT COUNT(*) FROM incidents").Scan(&count)
		inc.IncidentCode = fmt.Sprintf("INC-%d-%03d", time.Now().Year(), count+1)
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	inc.CreatedAt = now
	inc.UpdatedAt = now

	_, err := s.db.Exec(`
		INSERT INTO incidents 
		(id, incident_code, title, description, severity, status, lead_investigator,
		 affected_asset_id, linked_risk_id, root_cause, containment_action, containment_status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		inc.ID, inc.IncidentCode, inc.Title, inc.Description, inc.Severity, inc.Status,
		inc.LeadInvestigator, inc.AffectedAssetID, inc.LinkedRiskID, inc.RootCause,
		inc.ContainmentAction, inc.ContainmentStatus, inc.CreatedAt, inc.UpdatedAt,
	)
	if err != nil {
		return err
	}

	// Add initial timeline event
	timelineID := fmt.Sprintf("tl_%d", time.Now().UnixNano())
	_, _ = s.db.Exec(`
		INSERT INTO incident_timeline (id, incident_id, entry_type, description, actor, timestamp)
		VALUES (?, ?, 'StatusChange', ?, ?, ?)
	`, timelineID, inc.ID, fmt.Sprintf("Incident %s opened with severity %s", inc.IncidentCode, inc.Severity), inc.LeadInvestigator, now)

	return nil
}

// UpdateIncidentStatus advances the incident lifecycle (Open -> Investigating -> Containment -> Recovery -> Resolved -> Closed).
func (s *SecurityService) UpdateIncidentStatus(id, status, containmentStatus string) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	resolvedAt := ""
	if status == "Resolved" || status == "Closed" {
		resolvedAt = now
	}

	_, err := s.db.Exec(`
		UPDATE incidents SET status = ?, containment_status = ?, resolved_at = ?, updated_at = ? WHERE id = ?
	`, status, containmentStatus, resolvedAt, now, id)
	return err
}
