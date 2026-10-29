package service

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"cyberspring/pkg/riskguard/models"
)

// CalculateScore calculates risk score and categorical rating based on 1-5 scale.
// Formula: Likelihood × Impact (Range: 1 - 25)
// Thresholds:
//
//	20 - 25: Critical
//	15 - 19: High
//	8 - 14:  Medium
//	1 - 7:   Low
func CalculateScore(likelihood, impact int) (int, string) {
	if likelihood < 1 {
		likelihood = 1
	} else if likelihood > 5 {
		likelihood = 5
	}
	if impact < 1 {
		impact = 1
	} else if impact > 5 {
		impact = 5
	}

	score := likelihood * impact
	switch {
	case score >= 20:
		return score, "Critical"
	case score >= 15:
		return score, "High"
	case score >= 8:
		return score, "Medium"
	default:
		return score, "Low"
	}
}

// RiskService handles risk register operations and lifecycle management.
type RiskService struct {
	db *sql.DB
}

// NewRiskService creates a new RiskService instance.
func NewRiskService(db *sql.DB) *RiskService {
	return &RiskService{db: db}
}

// ListRisks retrieves risks filtered by status, category, severity rating, and search query.
func (s *RiskService) ListRisks(status, category, rating, query string) ([]models.Risk, error) {
	var conditions []string
	var args []interface{}

	if status != "" && status != "All" {
		conditions = append(conditions, "status = ?")
		args = append(args, status)
	}
	if category != "" && category != "All" {
		conditions = append(conditions, "category = ?")
		args = append(args, category)
	}
	if rating != "" && rating != "All" {
		conditions = append(conditions, "(inherent_rating = ? OR residual_rating = ?)")
		args = append(args, rating, rating)
	}
	if query != "" {
		like := "%" + query + "%"
		conditions = append(conditions, "(title LIKE ? OR description LIKE ? OR risk_code LIKE ? OR affected_assets LIKE ? OR risk_owner LIKE ?)")
		args = append(args, like, like, like, like, like)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	sqlQuery := fmt.Sprintf(`
		SELECT id, risk_code, title, description, category, business_impact, threat_scenario,
		       vulnerability_weakness, affected_assets, risk_owner, likelihood, impact,
		       inherent_score, inherent_rating, existing_controls, residual_likelihood, residual_impact,
		       residual_score, residual_rating, treatment_strategy, status, review_date, justification,
		       approver, approved_at, is_sample, created_at, updated_at
		FROM risks
		%s
		ORDER BY inherent_score DESC, updated_at DESC
	`, whereClause)

	rows, err := s.db.Query(sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query risks: %w", err)
	}
	defer rows.Close()

	var results []models.Risk
	for rows.Next() {
		var r models.Risk
		var isSample int
		err := rows.Scan(
			&r.ID, &r.RiskCode, &r.Title, &r.Description, &r.Category, &r.BusinessImpact,
			&r.ThreatScenario, &r.VulnerabilityWeakness, &r.AffectedAssets, &r.RiskOwner,
			&r.Likelihood, &r.Impact, &r.InherentScore, &r.InherentRating, &r.ExistingControls,
			&r.ResidualLikelihood, &r.ResidualImpact, &r.ResidualScore, &r.ResidualRating,
			&r.TreatmentStrategy, &r.Status, &r.ReviewDate, &r.Justification,
			&r.Approver, &r.ApprovedAt, &isSample, &r.CreatedAt, &r.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		r.IsSample = isSample == 1
		results = append(results, r)
	}

	return results, nil
}

// GetRisk fetches a single risk along with its mitigation tasks, mapped controls, and audit history.
func (s *RiskService) GetRisk(id string) (*models.Risk, error) {
	row := s.db.QueryRow(`
		SELECT id, risk_code, title, description, category, business_impact, threat_scenario,
		       vulnerability_weakness, affected_assets, risk_owner, likelihood, impact,
		       inherent_score, inherent_rating, existing_controls, residual_likelihood, residual_impact,
		       residual_score, residual_rating, treatment_strategy, status, review_date, justification,
		       approver, approved_at, is_sample, created_at, updated_at
		FROM risks
		WHERE id = ? OR risk_code = ?
	`, id, id)

	var r models.Risk
	var isSample int
	err := row.Scan(
		&r.ID, &r.RiskCode, &r.Title, &r.Description, &r.Category, &r.BusinessImpact,
		&r.ThreatScenario, &r.VulnerabilityWeakness, &r.AffectedAssets, &r.RiskOwner,
		&r.Likelihood, &r.Impact, &r.InherentScore, &r.InherentRating, &r.ExistingControls,
		&r.ResidualLikelihood, &r.ResidualImpact, &r.ResidualScore, &r.ResidualRating,
		&r.TreatmentStrategy, &r.Status, &r.ReviewDate, &r.Justification,
		&r.Approver, &r.ApprovedAt, &isSample, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	r.IsSample = isSample == 1

	// Mitigation Tasks
	taskRows, err := s.db.Query(`
		SELECT id, risk_id, title, description, owner, due_date, status, completed_at, created_at
		FROM mitigation_tasks
		WHERE risk_id = ?
		ORDER BY due_date ASC
	`, r.ID)
	if err == nil {
		defer taskRows.Close()
		for taskRows.Next() {
			var t models.MitigationTask
			if err := taskRows.Scan(&t.ID, &t.RiskID, &t.Title, &t.Description, &t.Owner, &t.DueDate, &t.Status, &t.CompletedAt, &t.CreatedAt); err == nil {
				r.MitigationTasks = append(r.MitigationTasks, t)
			}
		}
	}

	// Mapped Controls
	ctrlRows, err := s.db.Query(`
		SELECT c.control_id || ' - ' || c.title
		FROM compliance_controls c
		JOIN risk_control_mappings m ON c.id = m.control_id
		WHERE m.risk_id = ?
	`, r.ID)
	if err == nil {
		defer ctrlRows.Close()
		for ctrlRows.Next() {
			var label string
			if err := ctrlRows.Scan(&label); err == nil {
				r.MappedControls = append(r.MappedControls, label)
			}
		}
	}

	return &r, nil
}

// CreateRisk inserts a new risk, calculates scores, and records an audit event.
func (s *RiskService) CreateRisk(r *models.Risk) error {
	if r.ID == "" {
		r.ID = fmt.Sprintf("rsk_%d", time.Now().UnixNano())
	}

	// Generate next risk code if not provided
	if r.RiskCode == "" {
		var maxCode int
		_ = s.db.QueryRow("SELECT COALESCE(MAX(CAST(SUBSTR(risk_code, 5) AS INTEGER)), 100) FROM risks WHERE risk_code LIKE 'RSK-%'").Scan(&maxCode)
		r.RiskCode = fmt.Sprintf("RSK-%d", maxCode+1)
	}

	// Calculate Inherent and Residual Scores
	r.InherentScore, r.InherentRating = CalculateScore(r.Likelihood, r.Impact)
	if r.ResidualLikelihood == 0 {
		r.ResidualLikelihood = r.Likelihood
	}
	if r.ResidualImpact == 0 {
		r.ResidualImpact = r.Impact
	}
	r.ResidualScore, r.ResidualRating = CalculateScore(r.ResidualLikelihood, r.ResidualImpact)

	if r.Status == "" {
		r.Status = "Open"
	}
	if r.TreatmentStrategy == "" {
		r.TreatmentStrategy = "Mitigate"
	}

	now := time.Now().Format("2006-01-02 15:04:05")
	r.CreatedAt = now
	r.UpdatedAt = now

	_, err := s.db.Exec(`
		INSERT INTO risks 
		(id, risk_code, title, description, category, business_impact, threat_scenario,
		 vulnerability_weakness, affected_assets, risk_owner, likelihood, impact, inherent_score,
		 inherent_rating, existing_controls, residual_likelihood, residual_impact, residual_score,
		 residual_rating, treatment_strategy, status, review_date, justification, approver,
		 approved_at, is_sample, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
	`,
		r.ID, r.RiskCode, r.Title, r.Description, r.Category, r.BusinessImpact, r.ThreatScenario,
		r.VulnerabilityWeakness, r.AffectedAssets, r.RiskOwner, r.Likelihood, r.Impact, r.InherentScore,
		r.InherentRating, r.ExistingControls, r.ResidualLikelihood, r.ResidualImpact, r.ResidualScore,
		r.ResidualRating, r.TreatmentStrategy, r.Status, r.ReviewDate, r.Justification, r.Approver,
		r.ApprovedAt, r.CreatedAt, r.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create risk: %w", err)
	}

	// Record audit entry
	_, _ = s.db.Exec(`
		INSERT INTO audit_logs (id, action, entity_type, entity_id, details, actor)
		VALUES (?, 'CREATE', 'Risk', ?, ?, 'User')
	`, fmt.Sprintf("aud_%d", time.Now().UnixNano()), r.ID, fmt.Sprintf("Created risk %s: %s (Score: %d %s)", r.RiskCode, r.Title, r.InherentScore, r.InherentRating))

	return nil
}

// UpdateRisk updates an existing risk and recalculates scoring.
func (s *RiskService) UpdateRisk(r *models.Risk) error {
	r.InherentScore, r.InherentRating = CalculateScore(r.Likelihood, r.Impact)
	r.ResidualScore, r.ResidualRating = CalculateScore(r.ResidualLikelihood, r.ResidualImpact)
	now := time.Now().Format("2006-01-02 15:04:05")
	r.UpdatedAt = now

	_, err := s.db.Exec(`
		UPDATE risks SET
			title = ?, description = ?, category = ?, business_impact = ?,
			threat_scenario = ?, vulnerability_weakness = ?, affected_assets = ?,
			risk_owner = ?, likelihood = ?, impact = ?, inherent_score = ?,
			inherent_rating = ?, existing_controls = ?, residual_likelihood = ?,
			residual_impact = ?, residual_score = ?, residual_rating = ?,
			treatment_strategy = ?, status = ?, review_date = ?, justification = ?,
			approver = ?, approved_at = ?, updated_at = ?
		WHERE id = ?
	`,
		r.Title, r.Description, r.Category, r.BusinessImpact,
		r.ThreatScenario, r.VulnerabilityWeakness, r.AffectedAssets,
		r.RiskOwner, r.Likelihood, r.Impact, r.InherentScore,
		r.InherentRating, r.ExistingControls, r.ResidualLikelihood,
		r.ResidualImpact, r.ResidualScore, r.ResidualRating,
		r.TreatmentStrategy, r.Status, r.ReviewDate, r.Justification,
		r.Approver, r.ApprovedAt, r.UpdatedAt, r.ID,
	)
	return err
}

// AcceptRisk records formal approval, justification, and timestamp for risk acceptance.
func (s *RiskService) AcceptRisk(id, justification, approver string) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	reviewDate := time.Now().AddDate(0, 6, 0).Format("2006-01-02") // 6-month review default

	_, err := s.db.Exec(`
		UPDATE risks SET
			treatment_strategy = 'Accept',
			status = 'Accepted',
			justification = ?,
			approver = ?,
			approved_at = ?,
			review_date = ?,
			updated_at = ?
		WHERE id = ?
	`, justification, approver, now, reviewDate, now, id)
	return err
}

// DeleteRisk deletes a risk and its associated tasks.
func (s *RiskService) DeleteRisk(id string) error {
	_, err := s.db.Exec("DELETE FROM risks WHERE id = ?", id)
	return err
}

// AddMitigationTask creates a new actionable task linked to a risk.
func (s *RiskService) AddMitigationTask(t *models.MitigationTask) error {
	if t.ID == "" {
		t.ID = fmt.Sprintf("tsk_%d", time.Now().UnixNano())
	}
	if t.Status == "" {
		t.Status = "Not Started"
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	t.CreatedAt = now

	_, err := s.db.Exec(`
		INSERT INTO mitigation_tasks (id, risk_id, title, description, owner, due_date, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, t.ID, t.RiskID, t.Title, t.Description, t.Owner, t.DueDate, t.Status, t.CreatedAt)
	return err
}

// UpdateTaskStatus updates task progress.
func (s *RiskService) UpdateTaskStatus(taskID, status string) error {
	completedAt := ""
	if status == "Completed" {
		completedAt = time.Now().Format("2006-01-02 15:04:05")
	}
	_, err := s.db.Exec("UPDATE mitigation_tasks SET status = ?, completed_at = ? WHERE id = ?", status, completedAt, taskID)
	return err
}

// GetHeatmapCounts aggregates active risks across the 5x5 Likelihood x Impact matrix.
func (s *RiskService) GetHeatmapCounts() (map[string]int, error) {
	counts := make(map[string]int)
	// Initialize all 25 cells to 0
	for l := 1; l <= 5; l++ {
		for i := 1; i <= 5; i++ {
			counts[fmt.Sprintf("%d-%d", l, i)] = 0
		}
	}

	rows, err := s.db.Query("SELECT likelihood, impact, COUNT(*) FROM risks WHERE status != 'Closed' GROUP BY likelihood, impact")
	if err != nil {
		return counts, err
	}
	defer rows.Close()

	for rows.Next() {
		var l, imp, cnt int
		if err := rows.Scan(&l, &imp, &cnt); err == nil {
			counts[fmt.Sprintf("%d-%d", l, imp)] = cnt
		}
	}
	return counts, nil
}

// GetRiskAppetiteThreshold retrieves the configured risk appetite threshold.
func (s *RiskService) GetRiskAppetiteThreshold() int {
	var valStr string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key = 'risk_appetite_threshold'").Scan(&valStr)
	if err == nil {
		if val, err := strconv.Atoi(valStr); err == nil {
			return val
		}
	}
	return 12 // Default
}
