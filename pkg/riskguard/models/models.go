package models

import "time"

// Settings represents global application configuration.
type Settings struct {
	ProductName           string `json:"product_name"`
	ScoringModel          string `json:"scoring_model"`
	RiskAppetiteThreshold int    `json:"risk_appetite_threshold"`
	Theme                 string `json:"theme"`
	WorkspaceMode         string `json:"workspace_mode"` // "sample" or "production"
	OrganizationName      string `json:"organization_name"`
}

// Risk represents an organizational security or business risk.
type Risk struct {
	ID                    string           `json:"id"`
	RiskCode              string           `json:"risk_code"`
	Title                 string           `json:"title"`
	Description           string           `json:"description"`
	Category              string           `json:"category"`
	BusinessImpact        string           `json:"business_impact"`
	ThreatScenario        string           `json:"threat_scenario"`
	VulnerabilityWeakness string           `json:"vulnerability_weakness"`
	AffectedAssets        string           `json:"affected_assets"`
	RiskOwner             string           `json:"risk_owner"`
	Likelihood            int              `json:"likelihood"`
	Impact                int              `json:"impact"`
	InherentScore         int              `json:"inherent_score"`
	InherentRating        string           `json:"inherent_rating"`
	ExistingControls      string           `json:"existing_controls"`
	ResidualLikelihood    int              `json:"residual_likelihood"`
	ResidualImpact        int              `json:"residual_impact"`
	ResidualScore         int              `json:"residual_score"`
	ResidualRating        string           `json:"residual_rating"`
	TreatmentStrategy     string           `json:"treatment_strategy"` // Mitigate, Accept, Transfer, Avoid
	Status                string           `json:"status"`             // Open, Under Review, Mitigated, Accepted, Closed
	ReviewDate            string           `json:"review_date"`
	Justification         string           `json:"justification"`
	Approver              string           `json:"approver"`
	ApprovedAt            string           `json:"approved_at"`
	IsSample              bool             `json:"is_sample"`
	CreatedAt             string           `json:"created_at"`
	UpdatedAt             string           `json:"updated_at"`
	MitigationTasks       []MitigationTask `json:"mitigation_tasks,omitempty"`
	MappedControls        []string         `json:"mapped_controls,omitempty"`
	History               []RiskHistory    `json:"history,omitempty"`
}

// MitigationTask tracks a specific treatment action.
type MitigationTask struct {
	ID          string `json:"id"`
	RiskID      string `json:"risk_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Owner       string `json:"owner"`
	DueDate     string `json:"due_date"`
	Status      string `json:"status"` // Not Started, In Progress, Completed, Overdue
	CompletedAt string `json:"completed_at,omitempty"`
	CreatedAt   string `json:"created_at"`
}

// RiskHistory records changes to risk scores, treatments, or status.
type RiskHistory struct {
	ID         string    `json:"id"`
	RiskID     string    `json:"risk_id"`
	ChangeType string    `json:"change_type"`
	FieldName  string    `json:"field_name"`
	OldValue   string    `json:"old_value"`
	NewValue   string    `json:"new_value"`
	Actor      string    `json:"actor"`
	Timestamp  time.Time `json:"timestamp"`
}

// Asset represents an IT device, cloud resource, or application.
type Asset struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Type            string `json:"type"` // Computer, Server, Cloud, Application, Network, Service
	Hostname        string `json:"hostname"`
	IPAddress       string `json:"ip_address"`
	OSName          string `json:"os_name"`
	OSVersion       string `json:"os_version"`
	Owner           string `json:"owner"`
	Department      string `json:"department"`
	Environment     string `json:"environment"`      // Production, Staging, Development
	Criticality     string `json:"criticality"`      // Critical, High, Medium, Low
	DataSensitivity string `json:"data_sensitivity"` // Confidential, Restricted, Internal, Public
	Notes           string `json:"notes"`
	IsLocalMachine  bool   `json:"is_local_machine"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
	LinkedRisks     int    `json:"linked_risks,omitempty"`
	LinkedVulns     int    `json:"linked_vulns,omitempty"`
	LinkedIncidents int    `json:"linked_incidents,omitempty"`
}

// Endpoint represents detailed security posture inspection for a device.
type Endpoint struct {
	ID               string                 `json:"id"`
	AssetID          string                 `json:"asset_id"`
	DeviceName       string                 `json:"device_name"`
	OS               string                 `json:"os"`
	OSVersion        string                 `json:"os_version"`
	Kernel           string                 `json:"kernel"`
	Arch             string                 `json:"arch"`
	FirewallStatus   string                 `json:"firewall_status"`   // Pass, Fail, Unknown, Unsupported
	EncryptionStatus string                 `json:"encryption_status"` // Pass, Fail, Unknown, Unsupported
	AntivirusStatus  string                 `json:"antivirus_status"`  // Pass, Fail, Unknown, Unsupported
	PatchStatus      string                 `json:"patch_status"`      // Pass, Fail, Unknown, Unsupported
	PostureScore     int                    `json:"posture_score"`     // 0-100
	Status           string                 `json:"status"`            // Online, Offline, Stale, Unhealthy
	LastCheckin      string                 `json:"last_checkin"`
	Software         []string               `json:"software"`
	Hardware         map[string]interface{} `json:"hardware"`
}

// Vulnerability represents a security vulnerability or finding (e.g. CVE).
type Vulnerability struct {
	ID                  string  `json:"id"`
	CVEID               string  `json:"cve_id"`
	Title               string  `json:"title"`
	Description         string  `json:"description"`
	Severity            string  `json:"severity"` // Critical, High, Medium, Low
	CVSSScore           float64 `json:"cvss_score"`
	AffectedSoftware    string  `json:"affected_software"`
	AffectedAssetID     string  `json:"affected_asset_id"`
	AffectedAssetName   string  `json:"affected_asset_name,omitempty"`
	LinkedRiskID        string  `json:"linked_risk_id"`
	LinkedRiskCode      string  `json:"linked_risk_code,omitempty"`
	RemediationGuidance string  `json:"remediation_guidance"`
	Owner               string  `json:"owner"`
	DueDate             string  `json:"due_date"`
	Status              string  `json:"status"` // Open, In Progress, Pending Verification, Patched, Accepted
	VerifiedAt          string  `json:"verified_at,omitempty"`
	CreatedAt           string  `json:"created_at"`
	UpdatedAt           string  `json:"updated_at"`
}

// Alert represents an ingested security telemetry event.
type Alert struct {
	ID              string                 `json:"id"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Source          string                 `json:"source"`
	Severity        string                 `json:"severity"`   // Critical, High, Medium, Low
	Confidence      string                 `json:"confidence"` // High, Medium, Low
	EvidenceJSON    map[string]interface{} `json:"evidence"`
	Status          string                 `json:"status"` // New, Triaged, Assigned, Resolved, Closed
	AffectedAssetID string                 `json:"affected_asset_id"`
	CreatedAt       string                 `json:"created_at"`
	UpdatedAt       string                 `json:"updated_at"`
}

// Incident represents a formal security investigation.
type Incident struct {
	ID                string             `json:"id"`
	IncidentCode      string             `json:"incident_code"`
	Title             string             `json:"title"`
	Description       string             `json:"description"`
	Severity          string             `json:"severity"`
	Status            string             `json:"status"` // Open, Investigating, Containment, Recovery, Resolved, Closed
	LeadInvestigator  string             `json:"lead_investigator"`
	AffectedAssetID   string             `json:"affected_asset_id"`
	AffectedAssetName string             `json:"affected_asset_name,omitempty"`
	LinkedRiskID      string             `json:"linked_risk_id"`
	RootCause         string             `json:"root_cause"`
	ContainmentAction string             `json:"containment_action"`
	ContainmentStatus string             `json:"containment_status"` // Pending, Confirmed, Failed, Unsupported
	ResolvedAt        string             `json:"resolved_at,omitempty"`
	CreatedAt         string             `json:"created_at"`
	UpdatedAt         string             `json:"updated_at"`
	Timeline          []IncidentTimeline `json:"timeline,omitempty"`
}

// IncidentTimeline represents chronological investigation steps.
type IncidentTimeline struct {
	ID          string `json:"id"`
	IncidentID  string `json:"incident_id"`
	EntryType   string `json:"entry_type"` // Note, StatusChange, ContainmentAction, EvidenceAdded
	Description string `json:"description"`
	Actor       string `json:"actor"`
	Timestamp   string `json:"timestamp"`
}

// ComplianceFramework represents an authoritative control catalog (e.g. ISO 27001).
type ComplianceFramework struct {
	ID          string              `json:"id"`
	Code        string              `json:"code"`
	Name        string              `json:"name"`
	Version     string              `json:"version"`
	Description string              `json:"description"`
	Source      string              `json:"source"`
	Controls    []ComplianceControl `json:"controls,omitempty"`
	CoveragePct float64             `json:"coverage_pct"`
}

// ComplianceControl represents an individual governance control requirement.
type ComplianceControl struct {
	ID                   string   `json:"id"`
	FrameworkID          string   `json:"framework_id"`
	ControlID            string   `json:"control_id"`
	Title                string   `json:"title"`
	Description          string   `json:"description"`
	Category             string   `json:"category"`
	Owner                string   `json:"owner"`
	ImplementationStatus string   `json:"implementation_status"` // Implemented, Partially Implemented, Planned, Not Implemented, Not Applicable
	ReviewDate           string   `json:"review_date"`
	GapDescription       string   `json:"gap_description"`
	CorrectiveAction     string   `json:"corrective_action"`
	MappedRiskIDs        []string `json:"mapped_risk_ids,omitempty"`
}

// Evidence represents an uploaded policy, screenshot, or audit document.
type Evidence struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	FileName    string `json:"file_name"`
	FilePath    string `json:"file_path"`
	FileSize    int64  `json:"file_size"`
	MimeType    string `json:"mime_type"`
	SHA256Hash  string `json:"sha256_hash"`
	EntityType  string `json:"entity_type"` // Risk, Control, Vulnerability, Incident, Asset
	EntityID    string `json:"entity_id"`
	UploadedBy  string `json:"uploaded_by"`
	CreatedAt   string `json:"created_at"`
}

// AuditLog tracks security-sensitive actions in the application.
type AuditLog struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	Details    string `json:"details"`
	Actor      string `json:"actor"`
	Timestamp  string `json:"timestamp"`
}

// OverviewSummary holds Level 1 metrics for the executive overview dashboard.
type OverviewSummary struct {
	TotalRisks           int            `json:"total_risks"`
	OpenRisks            int            `json:"open_risks"`
	CriticalRisks        int            `json:"critical_risks"`
	HighRisks            int            `json:"high_risks"`
	ExceedingAppetite    int            `json:"exceeding_appetite"`
	TotalEndpoints       int            `json:"total_endpoints"`
	HealthyEndpoints     int            `json:"healthy_endpoints"`
	UnhealthyEndpoints   int            `json:"unhealthy_endpoints"`
	TotalVulnerabilities int            `json:"total_vulnerabilities"`
	CriticalVulns        int            `json:"critical_vulns"`
	OpenIncidents        int            `json:"open_incidents"`
	OverdueActions       int            `json:"overdue_actions"`
	ComplianceAvgScore   float64        `json:"compliance_avg_score"`
	HeatmapCounts        map[string]int `json:"heatmap_counts"` // "L-I" -> count e.g. "5-5": 2
	NeedsAttention       []ActionItem   `json:"needs_attention"`
}

// ActionItem represents a critical item requiring immediate analyst attention.
type ActionItem struct {
	ID        string `json:"id"`
	Type      string `json:"type"` // "risk", "endpoint", "vulnerability", "incident"
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Owner     string `json:"owner"`
	DueDate   string `json:"due_date"`
	Reason    string `json:"reason"`
	TargetURL string `json:"target_url"`
}
