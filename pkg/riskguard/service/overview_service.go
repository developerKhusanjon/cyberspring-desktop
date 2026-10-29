package service

import (
	"database/sql"
	"time"

	"cyberspring/pkg/riskguard/models"
)

// OverviewService aggregates Level 1 executive summary metrics.
type OverviewService struct {
	db          *sql.DB
	riskService *RiskService
}

// NewOverviewService creates an OverviewService.
func NewOverviewService(db *sql.DB, riskService *RiskService) *OverviewService {
	return &OverviewService{
		db:          db,
		riskService: riskService,
	}
}

// GetOverviewSummary computes the complete Level 1 operational dashboard metrics.
func (s *OverviewService) GetOverviewSummary() (*models.OverviewSummary, error) {
	summary := &models.OverviewSummary{
		NeedsAttention: []models.ActionItem{},
	}

	appetite := s.riskService.GetRiskAppetiteThreshold()

	// 1. Risk Metrics
	_ = s.db.QueryRow("SELECT COUNT(*) FROM risks").Scan(&summary.TotalRisks)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM risks WHERE status != 'Closed'").Scan(&summary.OpenRisks)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM risks WHERE status != 'Closed' AND inherent_rating = 'Critical'").Scan(&summary.CriticalRisks)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM risks WHERE status != 'Closed' AND inherent_rating = 'High'").Scan(&summary.HighRisks)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM risks WHERE status != 'Closed' AND inherent_score > ?", appetite).Scan(&summary.ExceedingAppetite)

	// 2. Endpoint Metrics
	_ = s.db.QueryRow("SELECT COUNT(*) FROM endpoints").Scan(&summary.TotalEndpoints)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM endpoints WHERE status = 'Online' AND posture_score >= 75").Scan(&summary.HealthyEndpoints)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM endpoints WHERE status = 'Unhealthy' OR posture_score < 75").Scan(&summary.UnhealthyEndpoints)

	// 3. Vulnerability Metrics
	_ = s.db.QueryRow("SELECT COUNT(*) FROM vulnerabilities WHERE status != 'Patched'").Scan(&summary.TotalVulnerabilities)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM vulnerabilities WHERE status != 'Patched' AND severity = 'Critical'").Scan(&summary.CriticalVulns)

	// 4. Incidents & Overdue Tasks
	_ = s.db.QueryRow("SELECT COUNT(*) FROM incidents WHERE status != 'Closed' AND status != 'Resolved'").Scan(&summary.OpenIncidents)

	today := time.Now().Format("2006-01-02")
	_ = s.db.QueryRow("SELECT COUNT(*) FROM mitigation_tasks WHERE status != 'Completed' AND due_date != '' AND due_date < ?", today).Scan(&summary.OverdueActions)

	// 5. Compliance Average Score
	var totalControls, implementedControls int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM compliance_controls").Scan(&totalControls)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM compliance_controls WHERE implementation_status = 'Implemented'").Scan(&implementedControls)
	if totalControls > 0 {
		summary.ComplianceAvgScore = float64(implementedControls) / float64(totalControls) * 100.0
	}

	// 6. Heatmap counts
	summary.HeatmapCounts, _ = s.riskService.GetHeatmapCounts()

	// 7. Action Items (Needs Attention Feed)
	// Overdue tasks
	taskRows, err := s.db.Query(`
		SELECT t.id, t.title, r.risk_code, t.owner, t.due_date
		FROM mitigation_tasks t
		JOIN risks r ON t.risk_id = r.id
		WHERE t.status != 'Completed' AND t.due_date != '' AND t.due_date < ?
		LIMIT 5
	`, today)
	if err == nil {
		for taskRows.Next() {
			var id, title, rCode, owner, due string
			if err := taskRows.Scan(&id, &title, &rCode, &owner, &due); err == nil {
				summary.NeedsAttention = append(summary.NeedsAttention, models.ActionItem{
					ID:        id,
					Type:      "task",
					Title:     title + " (" + rCode + ")",
					Severity:  "High",
					Owner:     owner,
					DueDate:   due,
					Reason:    "Overdue mitigation task requiring immediate follow-up",
					TargetURL: "#risks",
				})
			}
		}
		taskRows.Close()
	}

	// Critical unmitigated risks exceeding appetite
	riskRows, err := s.db.Query(`
		SELECT id, risk_code, title, risk_owner, inherent_score, review_date
		FROM risks
		WHERE status != 'Closed' AND inherent_score > ?
		ORDER BY inherent_score DESC
		LIMIT 5
	`, appetite)
	if err == nil {
		for riskRows.Next() {
			var id, code, title, owner, reviewDate string
			var score int
			if err := riskRows.Scan(&id, &code, &title, &owner, &score, &reviewDate); err == nil {
				summary.NeedsAttention = append(summary.NeedsAttention, models.ActionItem{
					ID:        id,
					Type:      "risk",
					Title:     code + ": " + title,
					Severity:  "Critical",
					Owner:     owner,
					DueDate:   reviewDate,
					Reason:    "Risk score exceeds organizational risk appetite threshold",
					TargetURL: "#risks",
				})
			}
		}
		riskRows.Close()
	}

	// Unhealthy endpoints
	epRows, err := s.db.Query(`
		SELECT id, device_name, os, posture_score
		FROM endpoints
		WHERE status = 'Unhealthy' OR posture_score < 75
		LIMIT 3
	`)
	if err == nil {
		for epRows.Next() {
			var id, name, osName string
			var score int
			if err := epRows.Scan(&id, &name, &osName, &score); err == nil {
				summary.NeedsAttention = append(summary.NeedsAttention, models.ActionItem{
					ID:        id,
					Type:      "endpoint",
					Title:     name + " (" + osName + ")",
					Severity:  "High",
					Owner:     "Endpoint Admin",
					DueDate:   "Immediate",
					Reason:    "Security posture score degraded (failed firewall or antivirus check)",
					TargetURL: "#endpoints",
				})
			}
		}
		epRows.Close()
	}

	return summary, nil
}
