package sast

import (
	"os"
	"testing"
)

func TestScannerDirectory(t *testing.T) {
	scanner := NewScanner()
	summary, err := scanner.ScanDirectory("../../test_samples/vulnerable_app")
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if summary.ScannedFiles == 0 {
		t.Errorf("expected > 0 scanned files, got %d", summary.ScannedFiles)
	}

	if summary.FindingsCount == 0 {
		t.Errorf("expected findings in vulnerable_app, got %d", summary.FindingsCount)
	}

	if summary.CriticalCount == 0 {
		t.Errorf("expected critical findings, got %d", summary.CriticalCount)
	}
}

func TestGenerateSARIF(t *testing.T) {
	scanner := NewScanner()
	summary, _ := scanner.ScanDirectory("../../test_samples/vulnerable_app")
	data, err := GenerateSARIF(summary)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}
	if len(data) == 0 {
		t.Errorf("expected non-empty SARIF JSON data")
	}
}

func TestApplyAndRevertPatch(t *testing.T) {
	// Create temporary dummy file for patching
	tmpFile, err := os.CreateTemp("", "vuln_sample_*.py")
	if err != nil {
		t.Fatalf("temp file error: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "import os\nAWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\n"
	_ = os.WriteFile(tmpFile.Name(), []byte(content), 0644)

	res, err := ApplyPatch(tmpFile.Name(), 2, "SEC-001")
	if err != nil {
		t.Fatalf("ApplyPatch error: %v", err)
	}
	if !res.Success {
		t.Errorf("expected patch success")
	}

	// Verify backup exists
	if _, err := os.Stat(res.BackupPath); os.IsNotExist(err) {
		t.Errorf("expected backup file %s to exist", res.BackupPath)
	}

	// Revert patch
	revRes, err := RevertPatch(tmpFile.Name())
	if err != nil {
		t.Fatalf("RevertPatch error: %v", err)
	}
	if !revRes.Success {
		t.Errorf("expected revert success")
	}

	// Check restored content
	restored, _ := os.ReadFile(tmpFile.Name())
	if string(restored) != content {
		t.Errorf("expected restored content %q, got %q", content, string(restored))
	}
}
