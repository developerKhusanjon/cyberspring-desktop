package service

import (
	"database/sql"
	"fmt"
	"time"

	"cyberspring/pkg/riskguard/models"
)

// CrossModuleService orchestrates unified data flow across Endpoints, Vulnerabilities, Risks, and Compliance.
type CrossModuleService struct {
	db          *sql.DB
	riskService *RiskService
}

// NewCrossModuleService creates a CrossModuleService.
func NewCrossModuleService(db *sql.DB, riskService *RiskService) *CrossModuleService {
	return &CrossModuleService{
		db:          db,
		riskService: riskService,
	}
}

// EscalateFindingRequest contains input parameters for escalating a technical finding into an enterprise risk.
type EscalateFindingRequest struct {
	VulnerabilityID string `json:"vulnerability_id"`
	CustomTitle     string `json:"custom_title"`
	Category        string `json:"category"`
	AssignedOwner   string `json:"assigned_owner"`
}

// EscalateFindingToRisk transforms an endpoint vulnerability finding into an enterprise risk,
// links affected assets, assigns mitigation tasks, and maps corresponding compliance controls.
func (s *CrossModuleService) EscalateFindingToRisk(req EscalateFindingRequest) (*models.Risk, error) {
	// 1. Fetch Vulnerability Record
	var v models.Vulnerability
	var assetName, assetCrit, assetOwner string
	err := s.db.QueryRow(`
		SELECT v.id, v.cve_id, v.title, v.description, v.severity, v.cvss_score,
		       v.affected_software, v.affected_asset_id, v.remediation_guidance, v.owner,
		       COALESCE(a.name, ''), COALESCE(a.criticality, 'Medium'), COALESCE(a.owner, '')
		FROM vulnerabilities v
		LEFT JOIN assets a ON v.affected_asset_id = a.id
		WHERE v.id = ?
	`, req.VulnerabilityID).Scan(
		&v.ID, &v.CVEID, &v.Title, &v.Description, &v.Severity, &v.CVSSScore,
		&v.AffectedSoftware, &v.AffectedAssetID, &v.RemediationGuidance, &v.Owner,
		&assetName, &assetCrit, &assetOwner,
	)
	if err != nil {
		return nil, fmt.Errorf("vulnerability not found: %w", err)
	}

	// 2. Derive Likelihood from Vulnerability Severity / CVSS
	likelihood := 3
	switch v.Severity {
	case "Critical":
		likelihood = 5
	case "High":
		likelihood = 4
	case "Medium":
		likelihood = 3
	default:
		likelihood = 2
	}

	// 3. Derive Business Impact from Asset Criticality
	impact := 3
	switch assetCrit {
	case "Critical":
		impact = 5
	case "High":
		impact = 4
	case "Medium":
		impact = 3
	default:
		impact = 2
	}

	// Determine Title and Category
	title := req.CustomTitle
	if title == "" {
		title = fmt.Sprintf("Unmitigated %s on %s (%s)", v.CVEID, assetName, v.AffectedSoftware)
	}
	category := req.Category
	if category == "" {
		category = "Technical Security"
	}
	owner := req.AssignedOwner
	if owner == "" {
		if v.Owner != "" {
			owner = v.Owner
		} else if assetOwner != "" {
			owner = assetOwner
		} else {
			owner = "SecOps Lead"
		}
	}

	// 4. Construct Risk Object
	risk := &models.Risk{
		Title:                 title,
		Description:           v.Description,
		Category:              category,
		BusinessImpact:        fmt.Sprintf("Potential exploitation of %s on %s (%s) could lead to service disruption or unauthorized data access.", v.CVEID, assetName, assetCrit),
		ThreatScenario:        fmt.Sprintf("Adversary exploits %s against %s.", v.CVEID, v.AffectedSoftware),
		VulnerabilityWeakness: fmt.Sprintf("%s (%s, CVSS %.1f)", v.CVEID, v.AffectedSoftware, v.CVSSScore),
		AffectedAssets:        assetName,
		RiskOwner:             owner,
		Likelihood:            likelihood,
		Impact:                impact,
		ExistingControls:      "Perimeter network firewall, operating system access controls.",
		ResidualLikelihood:    2,
		ResidualImpact:        impact,
		TreatmentStrategy:     "Mitigate",
		Status:                "Open",
		ReviewDate:            time.Now().AddDate(0, 3, 0).Format("2006-01-02"),
	}

	// 5. Create Risk in Register
	if err := s.riskService.CreateRisk(risk); err != nil {
		return nil, fmt.Errorf("failed to create risk: %w", err)
	}

	// 6. Cross-link Vulnerability to Risk and update status to "In Progress"
	now := time.Now().Format("2006-01-02 15:04:05")
	_, _ = s.db.Exec(`
		UPDATE vulnerabilities 
		SET linked_risk_id = ?, status = 'In Progress', updated_at = ?
		WHERE id = ?
	`, risk.ID, now, v.ID)

	// 7. Auto-Map Relevant Compliance Controls
	// CIS-7.1 Vulnerability Management & ISO A.8.8 Management of Technical Vulnerabilities
	controlIDs := []string{"ctrl_cis_7_1", "ctrl_iso_8_8", "ctrl_soc_cc7_1"}
	for _, cID := range controlIDs {
		_, _ = s.db.Exec(`INSERT OR IGNORE INTO risk_control_mappings (risk_id, control_id) VALUES (?, ?)`, risk.ID, cID)
	}

	// 8. Generate Remediation Task
	task := &models.MitigationTask{
		RiskID:      risk.ID,
		Title:       fmt.Sprintf("Patch %s: %s", v.CVEID, v.AffectedSoftware),
		Description: v.RemediationGuidance,
		Owner:       owner,
		DueDate:     time.Now().AddDate(0, 0, 14).Format("2006-01-02"),
		Status:      "In Progress",
	}
	_ = s.riskService.AddMitigationTask(task)

	// 9. Audit Event
	_, _ = s.db.Exec(`
		INSERT INTO audit_logs (id, action, entity_type, entity_id, details, actor)
		VALUES (?, 'ESCALATE', 'Vulnerability', ?, ?, 'User')
	`, fmt.Sprintf("aud_%d", time.Now().UnixNano()), v.ID, fmt.Sprintf("Escalated finding %s to risk %s (%s)", v.CVEID, risk.RiskCode, risk.Title))

	return s.riskService.GetRisk(risk.ID)
}
