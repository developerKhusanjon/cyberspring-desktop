package web

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"cyberspring/pkg/detection"
	"cyberspring/pkg/sast"
	"cyberspring/pkg/soar"
)

// TerminalExecResult holds the formatted output and side-effects of a command executed in the UI terminal.
type TerminalExecResult struct {
	Command    string `json:"command"`
	Output     string `json:"output"`
	ExitCode   int    `json:"exitCode"`
	DurationMs int64  `json:"durationMs"`
	Action     string `json:"action,omitempty"` // e.g. "refresh_sast", "refresh_rules", "refresh_soar", "refresh_status"
}

// ExecuteTerminalCommand handles interactive CLI commands sent from the web terminal.
func (s *Server) ExecuteTerminalCommand(rawCmd string) TerminalExecResult {
	start := time.Now()
	rawCmd = strings.TrimSpace(rawCmd)
	if rawCmd == "" {
		return TerminalExecResult{Command: "", Output: "", ExitCode: 0, DurationMs: 0}
	}

	// Strip leading ./cyberspring or cyberspring if present
	cmd := rawCmd
	if strings.HasPrefix(cmd, "./cyberspring ") {
		cmd = strings.TrimPrefix(cmd, "./cyberspring ")
	} else if strings.HasPrefix(cmd, "cyberspring ") {
		cmd = strings.TrimPrefix(cmd, "cyberspring ")
	}

	parts := parseCommandArgs(cmd)
	if len(parts) == 0 {
		return TerminalExecResult{Command: rawCmd, Output: "", ExitCode: 0}
	}

	mainArg := parts[0]
	var out strings.Builder
	exitCode := 0
	action := ""

	switch {
	case mainArg == "help" || mainArg == "--help" || mainArg == "-h":
		out.WriteString("\033[1;36m🌿 CyberSpring Interactive Controlling Center CLI\033[0m\n")
		out.WriteString("Enterprise SOC Analysis & SAST Vulnerability Detection Suite\n\n")
		out.WriteString("\033[1mCORE COMMANDS:\033[0m\n")
		out.WriteString("  \033[32mscan\033[0m [path]                 Scan directory or file for security weak points (SAST)\n")
		out.WriteString("  \033[32mtest\033[0m [rule_file]            Run detection replay fixtures & 30-day historical backtest\n")
		out.WriteString("  \033[32magent\033[0m \"<prompt>\"            Run detection engineering agent workflow\n")
		out.WriteString("  \033[32mreport\033[0m [path]               Generate SARIF 2.1.0 & Markdown audit reports\n")
		out.WriteString("  \033[32mremediate\033[0m <ruleId> <file>   Apply automated safe security patch to file\n")
		out.WriteString("  \033[32mrevert\033[0m <file>               Revert applied patch from .bak backup file\n\n")
		out.WriteString("\033[1mSOC & AUTOMATION COMMANDS:\033[0m\n")
		out.WriteString("  \033[32mstatus\033[0m                      Display live perimeter defense radar & fleet metrics\n")
		out.WriteString("  \033[32mincidents\033[0m                   List active security incidents and severity\n")
		out.WriteString("  \033[32msoar list\033[0m                   List registered incident response playbooks\n")
		out.WriteString("  \033[32msoar run\033[0m <playbook_id>      Trigger automated incident response playbook\n")
		out.WriteString("  \033[32mrules list\033[0m                  List loaded Sigma detection rules\n")
		out.WriteString("  \033[32mrules view\033[0m [file]           Display current rule YAML content\n\n")
		out.WriteString("\033[1mUTILITIES:\033[0m\n")
		out.WriteString("  \033[32mclear\033[0m                       Clear terminal output\n")
		out.WriteString("  \033[32mdown\033[0m | \033[32mstop\033[0m | \033[32mexit\033[0m      Shut down CyberSpring controlling center server\n")
		out.WriteString("  \033[32mpwd\033[0m | \033[32mls\033[0m | \033[32mcat\033[0m [file]       Standard safe system navigation\n")

	case mainArg == "down" || mainArg == "stop" || mainArg == "shutdown" || mainArg == "exit" || mainArg == "quit":
		out.WriteString("\033[1;33m🛑 Shutting down CyberSpring Controlling Center...\033[0m\n")
		out.WriteString("\033[32mServer process terminating. Run 'make up' or './up.sh' to restart.\033[0m\n")
		go func() {
			time.Sleep(400 * time.Millisecond)
			os.Exit(0)
		}()

	case mainArg == "scan" || mainArg == "-scan":
		targetPath := "test_samples/vulnerable_app"
		if len(parts) > 1 {
			targetPath = parts[1]
		}
		summary, err := s.sastScanner.ScanDirectory(targetPath)
		if err != nil {
			out.WriteString(fmt.Sprintf("\033[31mError scanning %s: %v\033[0m\n", targetPath, err))
			exitCode = 1
		} else {
			s.latestSAST = summary
			action = "refresh_sast"
			out.WriteString(fmt.Sprintf("\033[1;36m🔍 CyberSpring SAST Audit Complete: %s\033[0m\n", targetPath))
			out.WriteString(fmt.Sprintf("Scanned \033[1m%d files\033[0m (%d lines) in \033[32m%dms\033[0m\n", summary.ScannedFiles, summary.TotalLines, summary.DurationMs))
			out.WriteString(fmt.Sprintf("Discovered \033[1;31m%d security weak points\033[0m (CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d)\n\n",
				summary.FindingsCount, summary.CriticalCount, summary.HighCount, summary.MediumCount, summary.LowCount))

			for i, f := range summary.Findings {
				sevColor := "\033[33m" // medium
				if f.Severity == sast.SeverityCritical {
					sevColor = "\033[1;31m"
				} else if f.Severity == sast.SeverityHigh {
					sevColor = "\033[38;5;208m"
				}
				out.WriteString(fmt.Sprintf("%s[%d] %s: %s\033[0m\n", sevColor, i+1, f.Severity, f.Title))
				out.WriteString(fmt.Sprintf("    \033[2mLocation:\033[0m %s:%d | \033[2mCWE:\033[0m %s | \033[2mOWASP:\033[0m %s\n", f.FilePath, f.LineNumber, f.CWE, f.OWASP))
				out.WriteString(fmt.Sprintf("    \033[2mSnippet:\033[0m  \033[36m%s\033[0m\n", f.MatchSnippet))
				out.WriteString(fmt.Sprintf("    \033[2mRemedy:\033[0m   %s\n", f.Remedy))
				if f.RemedyDiff != "" {
					out.WriteString(fmt.Sprintf("    \033[2mDiff:\033[0m\n%s\n", indentANSI(f.RemedyDiff, "      ")))
				}
				out.WriteString("----------------------------------------------------------------------\n")
			}
		}

	case mainArg == "test" || mainArg == "-test":
		rulePath := s.ruleFilePath
		if len(parts) > 1 {
			rulePath = parts[1]
		}
		data, err := os.ReadFile(rulePath)
		if err != nil {
			out.WriteString(fmt.Sprintf("\033[31mError reading rule file %s: %v\033[0m\n", rulePath, err))
			exitCode = 1
		} else {
			_ = s.detEngine.LoadRulesFromYAML(data)
			testPath := s.testFilePath
			runner := detection.NewReplayRunner(s.detEngine)
			results, err := runner.RunTestSuite(testPath)
			if err != nil {
				out.WriteString(fmt.Sprintf("\033[31mError running replays: %v\033[0m\n", err))
				exitCode = 1
			} else {
				action = "refresh_rules"
				out.WriteString(fmt.Sprintf("\033[1;36m🧪 Running Detection Replays & Historical Backtest: %s\033[0m\n\n", rulePath))
				out.WriteString("\033[1mSTAGE 1 · Replay Fixtures:\033[0m\n")
				for _, r := range results {
					status := "\033[32m✅ PASSED\033[0m"
					if !r.Passed {
						status = "\033[31m❌ FAILED\033[0m"
					}
					out.WriteString(fmt.Sprintf("  %s | %-45s | Expect: %-5s | Actual: %s\n", status, r.CaseName, r.Expect, r.Actual))
				}

				out.WriteString("\n\033[1mSTAGE 2 · Historical 30-Day Backtest:\033[0m\n")
				bt := detection.NewBacktester(s.detEngine, 2)
				outcome := bt.RunBacktest(testPath, 412806, 30)
				out.WriteString(fmt.Sprintf("  Processed: \033[1m%d\033[0m historical telemetry events across %d days\n", outcome.Stage2TotalEvents, outcome.Stage2Days))
				out.WriteString(fmt.Sprintf("  Fires: \033[1m%d\033[0m (Triaged Benign: %d)\n", outcome.FiresCount, outcome.TriagedBenign))
				budgetStatus := "\033[32mwithin budget\033[0m"
				if !outcome.WithinBudget {
					budgetStatus = "\033[31mexceeds budget\033[0m"
				}
				out.WriteString(fmt.Sprintf("  False Positives: \033[1m%d\033[0m (Budget: %d) — %s\n", outcome.FalsePositives, outcome.FalsePositiveBudget, budgetStatus))
				if outcome.TuningRecommendation != "" {
					out.WriteString(fmt.Sprintf("\n\033[33m💡 Tuning Recommendation:\033[0m\n  %s\n", outcome.TuningRecommendation))
				}
			}
		}

	case mainArg == "agent" || mainArg == "-agent":
		prompt := "Write a detection for password spraying against our VPN"
		if len(parts) > 1 {
			prompt = strings.Join(parts[1:], " ")
		}
		// Strip quotes if present
		prompt = strings.Trim(prompt, `"'`)

		plan := detection.SynthesizeDetectionPlan(prompt, s.detEngine)
		s.latestAgentPlan = plan
		action = "refresh_agent"

		out.WriteString(fmt.Sprintf("\033[1;36m~/detections $ agent\033[0m\n> \033[1m%s\033[0m\n\n", prompt))
		for _, step := range plan.Steps {
			bulletColor := "\033[34m●\033[0m"
			if step.Type == "alert" {
				bulletColor = "\033[33m●\033[0m"
			} else if step.Type == "done" {
				bulletColor = "\033[32m●\033[0m"
			}
			out.WriteString(fmt.Sprintf("%s \033[1m%s\033[0m", bulletColor, step.Label))
			if step.Detail != "" {
				out.WriteString(fmt.Sprintf(" \033[2m%s\033[0m", step.Detail))
			}
			out.WriteString("\n")
		}

		out.WriteString(fmt.Sprintf("\n\033[1;32mSTAGE 1 · replay fixtures  %s · %s\033[0m\n", plan.BacktestOutcome.Stage1AttacksFired, plan.BacktestOutcome.Stage1BenignQuiet))
		out.WriteString(fmt.Sprintf("\033[1;36mSTAGE 2 · historical backtest - %d events · %d days\033[0m\n", plan.BacktestOutcome.Stage2TotalEvents, plan.BacktestOutcome.Stage2Days))
		out.WriteString(fmt.Sprintf("fires on 30 days of history: \033[1m%d\033[0m - triaged: \033[32mbenign\033[0m  false positives: \033[1m%d\033[0m in 30 days - \033[32mwithin budget\033[0m\n",
			plan.BacktestOutcome.FiresCount, plan.BacktestOutcome.FalsePositives))

	case mainArg == "report" || mainArg == "-report":
		targetPath := "test_samples/vulnerable_app"
		if len(parts) > 1 {
			targetPath = parts[1]
		}
		summary, err := s.sastScanner.ScanDirectory(targetPath)
		if err != nil {
			out.WriteString(fmt.Sprintf("\033[31mError generating reports: %v\033[0m\n", err))
			exitCode = 1
		} else {
			s.latestSAST = summary
			sarifData, _ := sast.GenerateSARIF(summary)
			sarifFile := "cyberspring_report.sarif"
			_ = os.WriteFile(sarifFile, sarifData, 0644)

			mdReport := sast.GenerateMarkdownReport(summary)
			mdFile := "cyberspring_report.md"
			_ = os.WriteFile(mdFile, []byte(mdReport), 0644)

			out.WriteString(fmt.Sprintf("\033[32m✅ Generated SARIF 2.1.0 report: %s (%d bytes)\033[0m\n", sarifFile, len(sarifData)))
			out.WriteString(fmt.Sprintf("\033[32m✅ Generated Markdown executive audit: %s (%d bytes)\033[0m\n", mdFile, len(mdReport)))
			out.WriteString(fmt.Sprintf("Web HTML preview available at: \033[36mhttp://127.0.0.1:%d/api/report/html\033[0m\n", s.port))
		}

	case mainArg == "remediate" || mainArg == "patch":
		if len(parts) < 3 {
			out.WriteString("\033[33mUsage: remediate <rule_id> <file_path> [line_number]\033[0m\nExample: remediate SEC-001 test_samples/vulnerable_app/cloud_storage.py\n")
			exitCode = 1
		} else {
			ruleID := parts[1]
			targetFile := parts[2]
			lineNum := 1
			// Attempt to find line number from latest scan if available
			if s.latestSAST != nil {
				for _, f := range s.latestSAST.Findings {
					if f.RuleID == ruleID && strings.Contains(f.FilePath, targetFile) {
						lineNum = f.LineNumber
						break
					}
				}
			}
			res, err := sast.ApplyPatch(targetFile, lineNum, ruleID)
			if err != nil {
				out.WriteString(fmt.Sprintf("\033[31mPatch error: %v\033[0m\n", err))
				exitCode = 1
			} else {
				action = "refresh_sast"
				out.WriteString(fmt.Sprintf("\033[32m✅ Successfully patched %s:%d\033[0m\n", res.FilePath, res.LineNumber))
				out.WriteString(fmt.Sprintf("   \033[31m- %s\033[0m\n", res.OriginalCode))
				out.WriteString(fmt.Sprintf("   \033[32m+ %s\033[0m\n", res.PatchedCode))
				out.WriteString(fmt.Sprintf("   Backup saved at: %s\n", res.BackupPath))
			}
		}

	case mainArg == "revert":
		if len(parts) < 2 {
			out.WriteString("\033[33mUsage: revert <file_path>\033[0m\nExample: revert test_samples/vulnerable_app/cloud_storage.py\n")
			exitCode = 1
		} else {
			res, err := sast.RevertPatch(parts[1])
			if err != nil {
				out.WriteString(fmt.Sprintf("\033[31mRevert error: %v\033[0m\n", err))
				exitCode = 1
			} else {
				action = "refresh_sast"
				out.WriteString(fmt.Sprintf("\033[32m✅ %s\033[0m\n", res.Message))
			}
		}

	case mainArg == "status":
		status := soar.GetSystemStatus()
		out.WriteString("\033[1;36m🌿 CyberSpring Controlling Center Telemetry\033[0m\n")
		out.WriteString(fmt.Sprintf("  Threats Blocked:       \033[1;32m%d%%\033[0m\n", status.ThreatsBlockedPercent))
		out.WriteString(fmt.Sprintf("  Open Incidents:        \033[1;31m%d\033[0m (High: %d, Med: %d, Low: %d)\n",
			status.OpenIncidentsTotal, status.HighSeverityCount, status.MediumSeverityCount, status.LowSeverityCount))
		out.WriteString(fmt.Sprintf("  Monitored Assets:      %d Servers (100%% Healthy), %d Workstations\n", status.ServersTotal, status.WorkstationsTotal))
		out.WriteString("\n\033[1mConnected Perimeter & Cloud Telemetry Feeds:\033[0m\n")
		for _, f := range status.Integrations {
			flag := "\033[32mHealthy\033[0m"
			if f.HasWarning {
				flag = "\033[33mWarning\033[0m"
			}
			out.WriteString(fmt.Sprintf("  • %-16s | %-18s | %2d events | Status: %s\n", f.Name, f.Category, f.EventCount, flag))
		}

	case mainArg == "incidents":
		status := soar.GetSystemStatus()
		out.WriteString(fmt.Sprintf("\033[1;36m🚨 Active Security Incidents (%d Total):\033[0m\n\n", len(status.Incidents)))
		for _, inc := range status.Incidents {
			sevColor := "\033[33m"
			if inc.Severity == "High" {
				sevColor = "\033[1;31m"
			} else if inc.Severity == "Low" {
				sevColor = "\033[34m"
			}
			out.WriteString(fmt.Sprintf("  %s[%s]\033[0m \033[1m%s\033[0m\n", sevColor, inc.Severity, inc.Title))
			out.WriteString(fmt.Sprintf("      ID: %s | Source: %s | Status: \033[1m%s\033[0m | Created: %s\n", inc.ID, inc.Source, inc.Status, inc.CreatedAt))
		}

	case mainArg == "soar":
		if len(parts) > 1 && parts[1] == "run" && len(parts) > 2 {
			pbID := parts[2]
			pb, err := s.soarManager.TriggerPlaybook(pbID, "Perimeter Firewall Gateway")
			if err != nil {
				out.WriteString(fmt.Sprintf("\033[31mError running playbook %s: %v\033[0m\n", pbID, err))
				exitCode = 1
			} else {
				action = "refresh_soar"
				out.WriteString(fmt.Sprintf("\033[32m⚡ Triggered SOAR Playbook: %s (%s)\033[0m\n", pb.Name, pb.ID))
				out.WriteString(fmt.Sprintf("   Target: %s | Status: %s | Total Executions: %d\n", pb.Target, pb.Status, pb.ExecCount))
			}
		} else {
			pbs := s.soarManager.ListPlaybooks()
			out.WriteString("\033[1;36m⚡ SOAR Incident Response Playbooks:\033[0m\n\n")
			for _, pb := range pbs {
				statusColor := "\033[32m"
				if pb.Status == soar.StatusRunning {
					statusColor = "\033[36m"
				}
				out.WriteString(fmt.Sprintf("  • \033[1m%-25s\033[0m [%s] Status: %s%s\033[0m (Execs: %d)\n", pb.Name, pb.ID, statusColor, pb.Status, pb.ExecCount))
				out.WriteString(fmt.Sprintf("    %s\n", pb.Description))
			}
		}

	case mainArg == "rules":
		if len(parts) > 1 && (parts[1] == "view" || parts[1] == "cat") {
			content, _ := os.ReadFile(s.ruleFilePath)
			out.WriteString(fmt.Sprintf("\033[1;36m📄 Detection Rule: %s\033[0m\n\n", s.ruleFilePath))
			out.WriteString(string(content))
		} else {
			out.WriteString("\033[1;36m📋 Active Sigma & Correlation Detection Rules:\033[0m\n\n")
			out.WriteString(fmt.Sprintf("  • \033[1m%s\033[0m\n    Correlating %s NPS/RADIUS events over %s window (threshold: %d)\n",
				s.ruleFilePath, s.detEngine.Timespan.String(), s.detEngine.Timespan.String(), s.detEngine.ThresholdGTE))
			out.WriteString(fmt.Sprintf("  • Test Fixtures: \033[1m%s\033[0m\n", s.testFilePath))
		}

	case mainArg == "pwd":
		if pwd, err := os.Getwd(); err == nil {
			out.WriteString(pwd + "\n")
		}

	case mainArg == "ls":
		target := "."
		if len(parts) > 1 {
			target = parts[1]
		}
		entries, err := os.ReadDir(target)
		if err != nil {
			out.WriteString(fmt.Sprintf("\033[31mError: %v\033[0m\n", err))
			exitCode = 1
		} else {
			for _, e := range entries {
				if e.IsDir() {
					out.WriteString(fmt.Sprintf("\033[1;34m%s/\033[0m  ", e.Name()))
				} else {
					out.WriteString(fmt.Sprintf("%s  ", e.Name()))
				}
			}
			out.WriteString("\n")
		}

	case mainArg == "cat":
		if len(parts) < 2 {
			out.WriteString("\033[33mUsage: cat <file>\033[0m\n")
			exitCode = 1
		} else {
			data, err := os.ReadFile(parts[1])
			if err != nil {
				out.WriteString(fmt.Sprintf("\033[31mError reading %s: %v\033[0m\n", parts[1], err))
				exitCode = 1
			} else {
				out.WriteString(string(data))
				if !strings.HasSuffix(string(data), "\n") {
					out.WriteString("\n")
				}
			}
		}

	default:
		// Safe execution of platform command
		safeBins := map[string]bool{
			"echo": true, "date": true, "whoami": true, "uname": true, "uptime": true,
		}
		if safeBins[mainArg] {
			cmdExec := exec.Command(mainArg, parts[1:]...)
			output, err := cmdExec.CombinedOutput()
			if err != nil {
				out.WriteString(fmt.Sprintf("\033[31mCommand error: %v\033[0m\n", err))
				exitCode = 1
			} else {
				out.WriteString(string(output))
			}
		} else {
			out.WriteString(fmt.Sprintf("\033[31mUnknown command: %s\033[0m\nType \033[32mhelp\033[0m to list available CyberSpring commands.\n", mainArg))
			exitCode = 127
		}
	}

	return TerminalExecResult{
		Command:    rawCmd,
		Output:     out.String(),
		ExitCode:   exitCode,
		DurationMs: time.Since(start).Milliseconds(),
		Action:     action,
	}
}

func parseCommandArgs(input string) []string {
	var args []string
	var current strings.Builder
	inQuotes := false
	quoteChar := byte(0)

	for i := 0; i < len(input); i++ {
		c := input[i]
		if inQuotes {
			if c == quoteChar {
				inQuotes = false
			} else {
				current.WriteByte(c)
			}
		} else {
			if c == '"' || c == '\'' {
				inQuotes = true
				quoteChar = c
			} else if c == ' ' || c == '\t' {
				if current.Len() > 0 {
					args = append(args, current.String())
					current.Reset()
				}
			} else {
				current.WriteByte(c)
			}
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

func indentANSI(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "-") {
			lines[i] = prefix + "\033[31m" + l + "\033[0m"
		} else if strings.HasPrefix(l, "+") {
			lines[i] = prefix + "\033[32m" + l + "\033[0m"
		} else {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n")
}
