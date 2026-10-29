package service

import (
	"bytes"
	"database/sql"
	"encoding/csv"
	"fmt"
	"time"
)

// ReportService generates CSV, Markdown, and printable executive audit reports.
type ReportService struct {
	db          *sql.DB
	riskService *RiskService
}

// NewReportService creates a ReportService.
func NewReportService(db *sql.DB, riskService *RiskService) *ReportService {
	return &ReportService{
		db:          db,
		riskService: riskService,
	}
}

// ExportRisksCSV generates an RFC 4180 compliant CSV export of the risk register.
func (s *ReportService) ExportRisksCSV() ([]byte, error) {
	risks, err := s.riskService.ListRisks("", "", "", "")
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Header
	header := []string{
		"Risk Code", "Title", "Category", "Status", "Risk Owner",
		"Likelihood", "Impact", "Inherent Score", "Inherent Rating",
		"Residual Score", "Residual Rating", "Treatment Strategy",
		"Affected Assets", "Existing Controls", "Review Date",
	}
	if err := writer.Write(header); err != nil {
		return nil, err
	}

	for _, r := range risks {
		row := []string{
			r.RiskCode,
			r.Title,
			r.Category,
			r.Status,
			r.RiskOwner,
			fmt.Sprintf("%d", r.Likelihood),
			fmt.Sprintf("%d", r.Impact),
			fmt.Sprintf("%d", r.InherentScore),
			r.InherentRating,
			fmt.Sprintf("%d", r.ResidualScore),
			r.ResidualRating,
			r.TreatmentStrategy,
			r.AffectedAssets,
			r.ExistingControls,
			r.ReviewDate,
		}
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	return buf.Bytes(), nil
}

// ExportExecutiveMarkdown generates a clean, printable Markdown executive report.
func (s *ReportService) ExportExecutiveMarkdown() (string, error) {
	risks, err := s.riskService.ListRisks("", "", "", "")
	if err != nil {
		return "", err
	}

	appetite := s.riskService.GetRiskAppetiteThreshold()
	now := time.Now().Format("2006-01-02 15:04:05")

	var buf bytes.Buffer
	buf.WriteString("# 🛡️ RiskGuard Desktop — Executive Risk & Endpoint Security Briefing\n\n")
	buf.WriteString(fmt.Sprintf("**Generated At:** `%s`  \n", now))
	buf.WriteString(fmt.Sprintf("**Scoring Methodology:** `Likelihood × Impact (1-5 Scale)`  \n"))
	buf.WriteString(fmt.Sprintf("**Risk Appetite Threshold:** `%d`  \n\n", appetite))
	buf.WriteString("---\n\n")

	buf.WriteString("## 1. Executive Summary Table\n\n")
	buf.WriteString("| Code | Risk Title | Inherent Score | Rating | Treatment | Status | Owner |\n")
	buf.WriteString("| :--- | :--- | :---: | :---: | :--- | :---: | :--- |\n")

	for _, r := range risks {
		flag := ""
		if r.InherentScore > appetite {
			flag = " ⚠️"
		}
		buf.WriteString(fmt.Sprintf("| **%s** | %s | %d%s | `%s` | %s | %s | %s |\n",
			r.RiskCode, r.Title, r.InherentScore, flag, r.InherentRating, r.TreatmentStrategy, r.Status, r.RiskOwner))
	}

	buf.WriteString("\n\n## 2. Inherent vs. Residual Exposure\n\n")
	buf.WriteString("| Code | Inherent Rating | Residual Rating | Risk Reduction |\n")
	buf.WriteString("| :--- | :---: | :---: | :---: |\n")

	for _, r := range risks {
		reduction := r.InherentScore - r.ResidualScore
		buf.WriteString(fmt.Sprintf("| **%s** | `%s` (%d) | `%s` (%d) | -%d pts |\n",
			r.RiskCode, r.InherentRating, r.InherentScore, r.ResidualRating, r.ResidualScore, reduction))
	}

	buf.WriteString("\n\n---\n*RiskGuard Desktop — Local-First Enterprise Risk Management & Endpoint Security*\n")

	return buf.String(), nil
}
