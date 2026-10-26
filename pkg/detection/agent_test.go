package detection

import (
	"strings"
	"testing"
)

func TestSynthesizeDetectionPlan(t *testing.T) {
	eng := NewEngine()

	// Test 1: VPN Password spray
	plan := SynthesizeDetectionPlan("Write a detection for password spraying against our VPN across 15 accounts inside 10 minutes", eng)
	if plan.Threshold != 15 {
		t.Errorf("expected threshold 15, got %d", plan.Threshold)
	}
	if !strings.Contains(plan.RuleYAML, "vpn_auth_failure") {
		t.Errorf("expected vpn_auth_failure in rule YAML")
	}
	if len(plan.Steps) == 0 {
		t.Errorf("expected agent steps")
	}

	// Test 2: AWS Root console login
	awsPlan := SynthesizeDetectionPlan("Detect AWS root account console login without MFA", eng)
	if awsPlan.Product != "aws" {
		t.Errorf("expected product aws, got %s", awsPlan.Product)
	}
	if !strings.Contains(awsPlan.RuleYAML, "aws_root_login_no_mfa") {
		t.Errorf("expected aws_root_login_no_mfa in rule YAML")
	}

	// Test 3: K8s privileged container
	k8sPlan := SynthesizeDetectionPlan("Alert on Kubernetes privileged pod creation", eng)
	if k8sPlan.Product != "kubernetes" {
		t.Errorf("expected product kubernetes, got %s", k8sPlan.Product)
	}
}
