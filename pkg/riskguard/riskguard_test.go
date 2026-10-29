package riskguard_test

import (
	"os"
	"path/filepath"
	"testing"

	"cyberspring/pkg/riskguard/db"
	"cyberspring/pkg/riskguard/models"
	"cyberspring/pkg/riskguard/service"
)

func setupTestDB(t *testing.T) string {
	tmpDir, err := os.MkdirTemp("", "riskguard_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := filepath.Join(tmpDir, "test_riskguard.db")
	return dbPath
}

func TestRiskGuardCoreWorkflow(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.RemoveAll(filepath.Dir(dbPath))

	database, _, err := db.InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer db.CloseDB()

	// 1. Seed Initial Data
	if err := db.SeedInitialData(database, true); err != nil {
		t.Fatalf("SeedInitialData failed: %v", err)
	}

	// 2. Risk Service Tests
	riskSvc := service.NewRiskService(database)

	// Test Scoring
	score, rating := service.CalculateScore(4, 5)
	if score != 20 || rating != "Critical" {
		t.Errorf("expected score 20 and Critical rating, got %d and %s", score, rating)
	}

	scoreLow, ratingLow := service.CalculateScore(2, 2)
	if scoreLow != 4 || ratingLow != "Low" {
		t.Errorf("expected score 4 and Low rating, got %d and %s", scoreLow, ratingLow)
	}

	// List seeded risks
	risks, err := riskSvc.ListRisks("", "", "", "")
	if err != nil {
		t.Fatalf("ListRisks failed: %v", err)
	}
	if len(risks) == 0 {
		t.Errorf("expected seeded risks, got 0")
	}

	// Create a new risk
	newRisk := &models.Risk{
		Title:                 "Test Database Credential Exposure",
		Category:              "Technical Security",
		Likelihood:            4,
		Impact:                4,
		TreatmentStrategy:     "Mitigate",
		VulnerabilityWeakness: "Plaintext connection string in legacy configuration file",
	}
	if err := riskSvc.CreateRisk(newRisk); err != nil {
		t.Fatalf("CreateRisk failed: %v", err)
	}
	if newRisk.InherentScore != 16 || newRisk.InherentRating != "High" {
		t.Errorf("expected InherentScore 16 High, got %d %s", newRisk.InherentScore, newRisk.InherentRating)
	}

	// Heatmap Counts
	heatmap, err := riskSvc.GetHeatmapCounts()
	if err != nil {
		t.Fatalf("GetHeatmapCounts failed: %v", err)
	}
	if heatmap["4-4"] == 0 {
		t.Errorf("expected at least 1 risk in heatmap cell 4-4")
	}

	// 3. Cross Module Escalation Test (The Core Differentiator!)
	crossSvc := service.NewCrossModuleService(database, riskSvc)
	escalatedRisk, err := crossSvc.EscalateFindingToRisk(service.EscalateFindingRequest{
		VulnerabilityID: "vuln_01",
		CustomTitle:     "Escalated Vulnerability Risk",
		Category:        "Compliance & Security",
		AssignedOwner:   "Test SecOps",
	})
	if err != nil {
		t.Fatalf("EscalateFindingToRisk failed: %v", err)
	}
	if escalatedRisk.InherentRating != "Critical" {
		t.Errorf("expected Critical rating on escalated risk, got %s", escalatedRisk.InherentRating)
	}
	if len(escalatedRisk.MitigationTasks) == 0 {
		t.Errorf("expected auto-generated mitigation task, got 0")
	}

	// 4. Endpoint Local Posture Check
	epSvc := service.NewEndpointService(database)
	localEp, err := epSvc.InspectLocalMachine()
	if err != nil {
		t.Fatalf("InspectLocalMachine failed: %v", err)
	}
	if localEp.OS == "" {
		t.Errorf("expected valid local OS, got empty")
	}

	// 5. Reports Test
	repSvc := service.NewReportService(database, riskSvc)
	csvData, err := repSvc.ExportRisksCSV()
	if err != nil || len(csvData) == 0 {
		t.Fatalf("ExportRisksCSV failed: %v", err)
	}

	mdReport, err := repSvc.ExportExecutiveMarkdown()
	if err != nil || len(mdReport) == 0 {
		t.Fatalf("ExportExecutiveMarkdown failed: %v", err)
	}
}
