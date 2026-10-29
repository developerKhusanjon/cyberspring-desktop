package service

import (
	"database/sql"
	"time"

	"cyberspring/pkg/riskguard/models"
)

// ComplianceService manages framework catalogs, control assessments, and gap analysis.
type ComplianceService struct {
	db *sql.DB
}

// NewComplianceService creates a ComplianceService.
func NewComplianceService(db *sql.DB) *ComplianceService {
	return &ComplianceService{db: db}
}

// ListFrameworks retrieves all loaded compliance frameworks with computed coverage metrics.
func (s *ComplianceService) ListFrameworks() ([]models.ComplianceFramework, error) {
	rows, err := s.db.Query(`
		SELECT id, code, name, version, description, source
		FROM compliance_frameworks
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var frameworks []models.ComplianceFramework
	for rows.Next() {
		var f models.ComplianceFramework
		if err := rows.Scan(&f.ID, &f.Code, &f.Name, &f.Version, &f.Description, &f.Source); err == nil {
			// Calculate coverage
			var total, implemented int
			_ = s.db.QueryRow(`SELECT COUNT(*) FROM compliance_controls WHERE framework_id = ?`, f.ID).Scan(&total)
			_ = s.db.QueryRow(`SELECT COUNT(*) FROM compliance_controls WHERE framework_id = ? AND implementation_status = 'Implemented'`, f.ID).Scan(&implemented)

			if total > 0 {
				f.CoveragePct = float64(implemented) / float64(total) * 100.0
			}
			frameworks = append(frameworks, f)
		}
	}
	return frameworks, nil
}

// ListControls retrieves controls for a framework with mapped risks.
func (s *ComplianceService) ListControls(frameworkID, status string) ([]models.ComplianceControl, error) {
	querySQL := `
		SELECT id, framework_id, control_id, title, description, category, owner,
		       implementation_status, review_date, gap_description, corrective_action
		FROM compliance_controls
		WHERE framework_id = ?
	`
	var args []interface{}
	args = append(args, frameworkID)

	if status != "" && status != "All" {
		querySQL += " AND implementation_status = ?"
		args = append(args, status)
	}
	querySQL += " ORDER BY control_id ASC"

	rows, err := s.db.Query(querySQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var controls []models.ComplianceControl
	for rows.Next() {
		var c models.ComplianceControl
		err := rows.Scan(
			&c.ID, &c.FrameworkID, &c.ControlID, &c.Title, &c.Description, &c.Category,
			&c.Owner, &c.ImplementationStatus, &c.ReviewDate, &c.GapDescription, &c.CorrectiveAction,
		)
		if err == nil {
			// Get mapped risks
			rRows, rErr := s.db.Query(`
				SELECT r.risk_code || ' - ' || r.title
				FROM risks r
				JOIN risk_control_mappings m ON r.id = m.risk_id
				WHERE m.control_id = ?
			`, c.ID)
			if rErr == nil {
				for rRows.Next() {
					var rLabel string
					if err := rRows.Scan(&rLabel); err == nil {
						c.MappedRiskIDs = append(c.MappedRiskIDs, rLabel)
					}
				}
				rRows.Close()
			}
			controls = append(controls, c)
		}
	}
	return controls, nil
}

// UpdateControlStatus updates control implementation status, gap details, and corrective action.
func (s *ComplianceService) UpdateControlStatus(controlID, status, gap, action, owner string) error {
	reviewDate := time.Now().Format("2006-01-02")
	_, err := s.db.Exec(`
		UPDATE compliance_controls SET
			implementation_status = ?,
			gap_description = ?,
			corrective_action = ?,
			owner = ?,
			review_date = ?
		WHERE id = ?
	`, status, gap, action, owner, reviewDate, controlID)
	return err
}

// MapRiskToControl links a business risk to a compliance control requirement.
func (s *ComplianceService) MapRiskToControl(riskID, controlID string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO risk_control_mappings (risk_id, control_id) VALUES (?, ?)`, riskID, controlID)
	return err
}
