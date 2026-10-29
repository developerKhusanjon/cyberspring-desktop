package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"cyberspring/pkg/riskguard/db"
	"cyberspring/pkg/riskguard/models"
	"cyberspring/pkg/riskguard/service"
)

// APIHandler coordinates REST endpoints for RiskGuard Desktop.
type APIHandler struct {
	database        *sql.DB
	riskService     *service.RiskService
	endpointService *service.EndpointService
	assetService    *service.AssetService
	secService      *service.SecurityService
	compService     *service.ComplianceService
	crossService    *service.CrossModuleService
	overviewService *service.OverviewService
	reportService   *service.ReportService
	evidenceService *service.EvidenceService
}

// NewAPIHandler initializes all services and returns an APIHandler.
func NewAPIHandler(database *sql.DB) *APIHandler {
	rSvc := service.NewRiskService(database)
	eSvc := service.NewEndpointService(database)
	aSvc := service.NewAssetService(database)
	sSvc := service.NewSecurityService(database)
	cSvc := service.NewComplianceService(database)
	xSvc := service.NewCrossModuleService(database, rSvc)
	oSvc := service.NewOverviewService(database, rSvc)
	repSvc := service.NewReportService(database, rSvc)
	evSvc := service.NewEvidenceService(database)

	return &APIHandler{
		database:        database,
		riskService:     rSvc,
		endpointService: eSvc,
		assetService:    aSvc,
		secService:      sSvc,
		compService:     cSvc,
		crossService:    xSvc,
		overviewService: oSvc,
		reportService:   repSvc,
		evidenceService: evSvc,
	}
}

// RegisterRoutes registers all RiskGuard endpoints on the provided HTTP mux.
func (h *APIHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/riskguard/overview", h.handleOverview)
	mux.HandleFunc("/api/riskguard/settings", h.handleSettings)
	mux.HandleFunc("/api/riskguard/workspace/clear", h.handleClearWorkspace)
	mux.HandleFunc("/api/riskguard/workspace/seed", h.handleSeedWorkspace)
	mux.HandleFunc("/api/riskguard/backup", h.handleBackup)

	// Risks
	mux.HandleFunc("/api/riskguard/risks", h.handleRisks)
	mux.HandleFunc("/api/riskguard/risks/", h.handleRiskSubroutes)
	mux.HandleFunc("/api/riskguard/tasks/", h.handleTaskSubroutes)

	// Assets
	mux.HandleFunc("/api/riskguard/assets", h.handleAssets)
	mux.HandleFunc("/api/riskguard/assets/", h.handleAssetSubroutes)

	// Endpoints
	mux.HandleFunc("/api/riskguard/endpoints", h.handleEndpoints)
	mux.HandleFunc("/api/riskguard/endpoints/local/inspect", h.handleInspectLocal)

	// Vulnerabilities
	mux.HandleFunc("/api/riskguard/vulnerabilities", h.handleVulnerabilities)
	mux.HandleFunc("/api/riskguard/vulnerabilities/", h.handleVulnSubroutes)

	// Cross-Module Escalation
	mux.HandleFunc("/api/riskguard/escalate", h.handleEscalate)

	// Incidents
	mux.HandleFunc("/api/riskguard/incidents", h.handleIncidents)
	mux.HandleFunc("/api/riskguard/incidents/", h.handleIncidentSubroutes)

	// Compliance
	mux.HandleFunc("/api/riskguard/compliance/frameworks", h.handleFrameworks)
	mux.HandleFunc("/api/riskguard/compliance/controls", h.handleControls)
	mux.HandleFunc("/api/riskguard/compliance/controls/", h.handleControlSubroutes)

	// Reports
	mux.HandleFunc("/api/riskguard/reports/csv", h.handleReportsCSV)
	mux.HandleFunc("/api/riskguard/reports/markdown", h.handleReportsMarkdown)
}

func (h *APIHandler) handleOverview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	summary, err := h.overviewService.GetOverviewSummary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(summary)
}

func (h *APIHandler) handleSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		var s models.Settings
		_ = h.database.QueryRow("SELECT value FROM settings WHERE key = 'product_name'").Scan(&s.ProductName)
		_ = h.database.QueryRow("SELECT value FROM settings WHERE key = 'scoring_model'").Scan(&s.ScoringModel)
		_ = h.database.QueryRow("SELECT value FROM settings WHERE key = 'theme'").Scan(&s.Theme)
		_ = h.database.QueryRow("SELECT value FROM settings WHERE key = 'workspace_mode'").Scan(&s.WorkspaceMode)
		_ = h.database.QueryRow("SELECT value FROM settings WHERE key = 'organization_name'").Scan(&s.OrganizationName)
		s.RiskAppetiteThreshold = h.riskService.GetRiskAppetiteThreshold()
		_ = json.NewEncoder(w).Encode(s)
		return
	}

	if r.Method == http.MethodPost {
		var s models.Settings
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if s.ProductName != "" {
			_, _ = h.database.Exec("UPDATE settings SET value = ? WHERE key = 'product_name'", s.ProductName)
		}
		if s.Theme != "" {
			_, _ = h.database.Exec("UPDATE settings SET value = ? WHERE key = 'theme'", s.Theme)
		}
		if s.RiskAppetiteThreshold > 0 {
			_, _ = h.database.Exec("UPDATE settings SET value = ? WHERE key = 'risk_appetite_threshold'", fmt.Sprintf("%d", s.RiskAppetiteThreshold))
		}
		if s.OrganizationName != "" {
			_, _ = h.database.Exec("UPDATE settings SET value = ? WHERE key = 'organization_name'", s.OrganizationName)
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (h *APIHandler) handleClearWorkspace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := db.ClearSampleWorkspace(h.database); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Sample workspace cleared. Clean workspace activated."})
}

func (h *APIHandler) handleSeedWorkspace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := db.SeedSampleWorkspace(h.database); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = h.database.Exec("UPDATE settings SET value = 'sample' WHERE key = 'workspace_mode'")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Sample demonstration workspace loaded."})
}

func (h *APIHandler) handleBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	currentDBPath := db.GetDBPath()
	dir := filepath.Dir(currentDBPath)
	backupName := fmt.Sprintf("riskguard_backup_%s.db", time.Now().Format("20060102_150405"))
	targetPath := filepath.Join(dir, backupName)

	if err := db.BackupDatabase(targetPath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"backup_path": targetPath,
		"backup_name": backupName,
	})
}

func (h *APIHandler) handleRisks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		q := r.URL.Query()
		risks, err := h.riskService.ListRisks(q.Get("status"), q.Get("category"), q.Get("rating"), q.Get("q"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(risks)
		return
	}

	if r.Method == http.MethodPost {
		var risk models.Risk
		if err := json.NewDecoder(r.Body).Decode(&risk); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := h.riskService.CreateRisk(&risk); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(risk)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (h *APIHandler) handleRiskSubroutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/riskguard/risks/"), "/")
	riskID := parts[0]

	if len(parts) == 1 {
		if r.Method == http.MethodGet {
			risk, err := h.riskService.GetRisk(riskID)
			if err != nil {
				http.Error(w, "risk not found", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(risk)
			return
		}
		if r.Method == http.MethodPut {
			var risk models.Risk
			if err := json.NewDecoder(r.Body).Decode(&risk); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			risk.ID = riskID
			if err := h.riskService.UpdateRisk(&risk); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
			return
		}
		if r.Method == http.MethodDelete {
			if err := h.riskService.DeleteRisk(riskID); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
			return
		}
	} else if len(parts) == 2 {
		subaction := parts[1]
		if subaction == "accept" && r.Method == http.MethodPost {
			var req struct {
				Justification string `json:"justification"`
				Approver      string `json:"approver"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if err := h.riskService.AcceptRisk(riskID, req.Justification, req.Approver); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
			return
		}
		if subaction == "tasks" && r.Method == http.MethodPost {
			var task models.MitigationTask
			if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
			task.RiskID = riskID
			if err := h.riskService.AddMitigationTask(&task); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(task)
			return
		}
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (h *APIHandler) handleTaskSubroutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	taskID := strings.TrimPrefix(r.URL.Path, "/api/riskguard/tasks/")

	if r.Method == http.MethodPut {
		var req struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if err := h.riskService.UpdateTaskStatus(taskID, req.Status); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (h *APIHandler) handleAssets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		q := r.URL.Query()
		assets, err := h.assetService.ListAssets(q.Get("type"), q.Get("criticality"), q.Get("q"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(assets)
		return
	}

	if r.Method == http.MethodPost {
		var a models.Asset
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if err := h.assetService.CreateAsset(&a); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(a)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (h *APIHandler) handleAssetSubroutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	assetID := strings.TrimPrefix(r.URL.Path, "/api/riskguard/assets/")

	if r.Method == http.MethodPut {
		var a models.Asset
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		a.ID = assetID
		if err := h.assetService.UpdateAsset(&a); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}

	if r.Method == http.MethodDelete {
		if err := h.assetService.DeleteAsset(assetID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (h *APIHandler) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	endpoints, err := h.endpointService.ListEndpoints()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(endpoints)
}

func (h *APIHandler) handleInspectLocal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	ep, err := h.endpointService.InspectLocalMachine()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(ep)
}

func (h *APIHandler) handleVulnerabilities(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		q := r.URL.Query()
		vulns, err := h.secService.ListVulnerabilities(q.Get("severity"), q.Get("status"), q.Get("q"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(vulns)
		return
	}

	if r.Method == http.MethodPost {
		var v models.Vulnerability
		if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if err := h.secService.CreateVulnerability(&v); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(v)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (h *APIHandler) handleVulnSubroutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/riskguard/vulnerabilities/"), "/")
	vulnID := parts[0]

	if len(parts) == 2 && parts[1] == "status" && r.Method == http.MethodPut {
		var req struct {
			Status string `json:"status"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if err := h.secService.UpdateVulnerabilityStatus(vulnID, req.Status); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (h *APIHandler) handleEscalate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req service.EscalateFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	risk, err := h.crossService.EscalateFindingToRisk(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(risk)
}

func (h *APIHandler) handleIncidents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		q := r.URL.Query()
		incidents, err := h.secService.ListIncidents(q.Get("status"), q.Get("q"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(incidents)
		return
	}

	if r.Method == http.MethodPost {
		var inc models.Incident
		if err := json.NewDecoder(r.Body).Decode(&inc); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if err := h.secService.CreateIncident(&inc); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(inc)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (h *APIHandler) handleIncidentSubroutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/riskguard/incidents/"), "/")
	incID := parts[0]

	if len(parts) == 2 && parts[1] == "status" && r.Method == http.MethodPut {
		var req struct {
			Status            string `json:"status"`
			ContainmentStatus string `json:"containment_status"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if err := h.secService.UpdateIncidentStatus(incID, req.Status, req.ContainmentStatus); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (h *APIHandler) handleFrameworks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fws, err := h.compService.ListFrameworks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(fws)
}

func (h *APIHandler) handleControls(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	q := r.URL.Query()
	controls, err := h.compService.ListControls(q.Get("framework_id"), q.Get("status"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(controls)
}

func (h *APIHandler) handleControlSubroutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	controlID := strings.TrimPrefix(r.URL.Path, "/api/riskguard/compliance/controls/")

	if r.Method == http.MethodPut {
		var req struct {
			Status string `json:"implementation_status"`
			Gap    string `json:"gap_description"`
			Action string `json:"corrective_action"`
			Owner  string `json:"owner"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if err := h.compService.UpdateControlStatus(controlID, req.Status, req.Gap, req.Action, req.Owner); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (h *APIHandler) handleReportsCSV(w http.ResponseWriter, r *http.Request) {
	csvBytes, err := h.reportService.ExportRisksCSV()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=riskguard_risks_%s.csv", time.Now().Format("20060102")))
	_, _ = w.Write(csvBytes)
}

func (h *APIHandler) handleReportsMarkdown(w http.ResponseWriter, r *http.Request) {
	mdStr, err := h.reportService.ExportExecutiveMarkdown()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=riskguard_briefing_%s.md", time.Now().Format("20060102")))
	_, _ = w.Write([]byte(mdStr))
}
