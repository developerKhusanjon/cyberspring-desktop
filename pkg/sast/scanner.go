package sast

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Finding represents an individual discovered security weakness in source code.
type Finding struct {
	ID             string   `json:"id"`
	RuleID         string   `json:"ruleId"`
	Title          string   `json:"title"`
	Category       string   `json:"category"`
	Severity       Severity `json:"severity"`
	CWE            string   `json:"cwe"`
	OWASP          string   `json:"owasp"`
	FilePath       string   `json:"filePath"`
	LineNumber     int      `json:"lineNumber"`
	MatchSnippet   string   `json:"matchSnippet"`
	ContextSnippet string   `json:"contextSnippet"`
	Description    string   `json:"description"`
	Remedy         string   `json:"remedy"`
	RemedyDiff     string   `json:"remedyDiff"`
}

// ScanSummary aggregates high-level stats from a SAST run.
type ScanSummary struct {
	TargetPath     string         `json:"targetPath"`
	ScannedFiles   int            `json:"scannedFiles"`
	TotalLines     int            `json:"totalLines"`
	DurationMs     int64          `json:"durationMs"`
	FindingsCount  int            `json:"findingsCount"`
	CriticalCount  int            `json:"criticalCount"`
	HighCount      int            `json:"highCount"`
	MediumCount    int            `json:"mediumCount"`
	LowCount       int            `json:"lowCount"`
	Findings       []Finding      `json:"findings"`
	CategoryCounts map[string]int `json:"categoryCounts"`
}

// Scanner performs concurrent pattern and syntax auditing over source trees.
type Scanner struct {
	rules []VulnerabilityRule
}

// NewScanner instantiates a scanner loaded with default or custom rules.
func NewScanner(customRules ...VulnerabilityRule) *Scanner {
	rules := DefaultRules()
	if len(customRules) > 0 {
		rules = append(rules, customRules...)
	}
	return &Scanner{rules: rules}
}

// GetRules returns all currently loaded SAST detection rules.
func (s *Scanner) GetRules() []VulnerabilityRule {
	return s.rules
}

// AddRule registers a new custom SAST detection rule.
func (s *Scanner) AddRule(rule VulnerabilityRule) {
	s.rules = append(s.rules, rule)
}

// ScanDirectory walks the given directory path concurrently and audits all code files.
func (s *Scanner) ScanDirectory(rootPath string) (*ScanSummary, error) {
	start := time.Now()
	var (
		mu           sync.Mutex
		findings     []Finding
		scannedFiles int
		totalLines   int
		catCounts    = make(map[string]int)
	)

	// Ignore common non-code / dependency folders
	skipDirs := map[string]bool{
		".git": true, "node_modules": true, "vendor": true, "dist": true,
		"build": true, ".idea": true, ".vscode": true, "__pycache__": true,
	}

	supportedExts := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true,
		".tsx": true, ".java": true, ".php": true, ".rb": true, ".c": true,
		".cpp": true, ".sh": true, ".yaml": true, ".yml": true, ".env": true,
	}

	type fileJob struct {
		path string
	}

	jobs := make(chan fileJob, 100)
	var wg sync.WaitGroup

	// Worker pool (number of CPUs * 2)
	workerCount := 8
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				fFindings, lines, err := s.scanFile(job.path)
				if err != nil {
					continue
				}

				mu.Lock()
				scannedFiles++
				totalLines += lines
				for _, f := range fFindings {
					findings = append(findings, f)
					catCounts[f.Category]++
				}
				mu.Unlock()
			}
		}()
	}

	// Walk tree and feed files to workers
	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if supportedExts[ext] || d.Name() == ".env" || strings.HasPrefix(d.Name(), ".env.") {
			jobs <- fileJob{path: path}
		}
		return nil
	})

	close(jobs)
	wg.Wait()

	if err != nil {
		return nil, err
	}

	var crit, high, med, low int
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			crit++
		case SeverityHigh:
			high++
		case SeverityMedium:
			med++
		case SeverityLow:
			low++
		}
	}

	return &ScanSummary{
		TargetPath:     rootPath,
		ScannedFiles:   scannedFiles,
		TotalLines:     totalLines,
		DurationMs:     time.Since(start).Milliseconds(),
		FindingsCount:  len(findings),
		CriticalCount:  crit,
		HighCount:      high,
		MediumCount:    med,
		LowCount:       low,
		Findings:       findings,
		CategoryCounts: catCounts,
	}, nil
}

// scanFile audits a single source code file against the rule database.
func (s *Scanner) scanFile(filePath string) ([]Finding, int, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, 0, err
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	var findings []Finding

	scanner := bufio.NewScanner(bytes.NewReader(data))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	for lineIdx, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip empty lines or standard pure single-line comments
		if len(trimmed) == 0 || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		for _, rule := range s.rules {
			// Check language eligibility
			matchesLang := false
			for _, lang := range rule.Languages {
				if lang == "all" || lang == ext {
					matchesLang = true
					break
				}
			}
			if !matchesLang {
				continue
			}

			// Pattern test
			if rule.Pattern != nil && rule.Pattern.MatchString(line) {
				// Construct context snippet (2 lines before and 2 lines after)
				startCtx := lineIdx - 2
				if startCtx < 0 {
					startCtx = 0
				}
				endCtx := lineIdx + 2
				if endCtx >= len(lines) {
					endCtx = len(lines) - 1
				}

				var ctxBuilder strings.Builder
				for c := startCtx; c <= endCtx; c++ {
					prefix := "  "
					if c == lineIdx {
						prefix = "> "
					}
					ctxBuilder.WriteString(prefix)
					ctxBuilder.WriteString(lines[c])
					ctxBuilder.WriteString("\n")
				}

				findings = append(findings, Finding{
					ID:             rule.ID,
					RuleID:         rule.ID,
					Title:          rule.Name,
					Category:       rule.Category,
					Severity:       rule.Severity,
					CWE:            rule.CWE,
					OWASP:          rule.OWASP,
					FilePath:       filePath,
					LineNumber:     lineIdx + 1,
					MatchSnippet:   trimmed,
					ContextSnippet: ctxBuilder.String(),
					Description:    rule.Description,
					Remedy:         rule.Remedy,
					RemedyDiff:     rule.RemedyDiff,
				})
			}
		}
	}

	return findings, len(lines), nil
}
