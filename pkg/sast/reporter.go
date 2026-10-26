package sast

import (
	"encoding/json"
	"fmt"
	"strings"
)

// GenerateSARIF produces standard SARIF 2.1.0 JSON format for CI/CD integrations.
func GenerateSARIF(summary *ScanSummary) ([]byte, error) {
	type SarifMessage struct {
		Text string `json:"text"`
	}

	type SarifRegion struct {
		StartLine int `json:"startLine"`
	}

	type SarifArtifactLocation struct {
		URI string `json:"uri"`
	}

	type SarifPhysicalLocation struct {
		ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
		Region           SarifRegion           `json:"region"`
	}

	type SarifLocation struct {
		PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
	}

	type SarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   SarifMessage    `json:"message"`
		Locations []SarifLocation `json:"locations"`
	}

	type SarifRule struct {
		ID               string       `json:"id"`
		Name             string       `json:"name"`
		ShortDescription SarifMessage `json:"shortDescription"`
	}

	type SarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []SarifRule `json:"rules"`
	}

	type SarifTool struct {
		Driver SarifDriver `json:"driver"`
	}

	type SarifRun struct {
		Tool    SarifTool     `json:"tool"`
		Results []SarifResult `json:"results"`
	}

	type SarifReport struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []SarifRun `json:"runs"`
	}

	ruleMap := make(map[string]SarifRule)
	var results []SarifResult

	for _, f := range summary.Findings {
		level := "warning"
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh {
			level = "error"
		} else if f.Severity == SeverityLow {
			level = "note"
		}

		if _, exists := ruleMap[f.RuleID]; !exists {
			ruleMap[f.RuleID] = SarifRule{
				ID:   f.RuleID,
				Name: f.Title,
				ShortDescription: SarifMessage{
					Text: f.Description,
				},
			}
		}

		results = append(results, SarifResult{
			RuleID: f.RuleID,
			Level:  level,
			Message: SarifMessage{
				Text: fmt.Sprintf("[%s] %s: %s", f.CWE, f.Title, f.Remedy),
			},
			Locations: []SarifLocation{
				{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifArtifactLocation{
							URI: f.FilePath,
						},
						Region: SarifRegion{
							StartLine: f.LineNumber,
						},
					},
				},
			},
		})
	}

	var rules []SarifRule
	for _, r := range ruleMap {
		rules = append(rules, r)
	}

	report := SarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "CyberSpring SAST",
						Version:        "1.0.0",
						InformationURI: "https://cyberspring.secops.local",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(report, "", "  ")
}

// GenerateMarkdownReport creates a clean markdown summary report
func GenerateMarkdownReport(summary *ScanSummary) string {
	var sb strings.Builder
	sb.WriteString("# CyberSpring Vulnerability & SAST Audit Report\n\n")
	sb.WriteString(fmt.Sprintf("**Target Path:** `%s`  \n", summary.TargetPath))
	sb.WriteString(fmt.Sprintf("**Scanned Files:** %d | **Total Lines:** %d | **Scan Time:** %dms  \n", summary.ScannedFiles, summary.TotalLines, summary.DurationMs))
	sb.WriteString(fmt.Sprintf("**Total Findings:** %d (Critical: %d, High: %d, Medium: %d, Low: %d)\n\n",
		summary.FindingsCount, summary.CriticalCount, summary.HighCount, summary.MediumCount, summary.LowCount))

	sb.WriteString("## Findings Breakdown\n\n")
	for i, f := range summary.Findings {
		sb.WriteString(fmt.Sprintf("### %d. [%s] %s\n", i+1, f.Severity, f.Title))
		sb.WriteString(fmt.Sprintf("- **Location:** `%s:%d`\n", f.FilePath, f.LineNumber))
		sb.WriteString(fmt.Sprintf("- **CWE / OWASP:** `%s` | `%s`\n", f.CWE, f.OWASP))
		sb.WriteString(fmt.Sprintf("- **Description:** %s\n", f.Description))
		sb.WriteString(fmt.Sprintf("- **Remediation:** %s\n\n", f.Remedy))
		sb.WriteString("```diff\n")
		sb.WriteString(f.RemedyDiff)
		sb.WriteString("\n```\n\n")
	}

	return sb.String()
}
