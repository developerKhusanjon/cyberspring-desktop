package detection

import (
	"os"
	"path/filepath"
)

// DefaultRuleYAML contains the production Sigma rule definition embedded for zero-dependency standalone execution.
const DefaultRuleYAML = `title: VPN Password Spray - Many Accounts, One Source
name: vpn_auth_failure
status: production
logsource:
  product: windows
  service: nps      # RADIUS auth for the VPN gateway
detection:
  selection:
    EventID: 6273   # NPS: VPN access denied
  filter_authorised_scanners:
    SourceIP: [10.20.8.41, 10.20.8.42]
  condition: selection and not filter_authorised_scanners
---
title: Correlation - many accounts, one source IP
correlation:
  type: value_count
  rules: [vpn_auth_failure]
  group-by: [SourceIP]
  timespan: 10m
  condition:
    field: TargetUserName
    gte: 12        # raised: shared-NAT noise
  level: high
`

// DefaultTestYAML contains unit test replay fixtures embedded for zero-dependency standalone execution.
const DefaultTestYAML = `cases:
  - replay: attack/spray_50_accounts_one_ip.jsonl     # expect: fire
  - replay: attack/spray_12_accounts_9_minutes.jsonl  # expect: fire
  - replay: attack/spray_vpn_gateway_burst.jsonl      # expect: fire
  - replay: attack/spray_mixed_success_tail.jsonl     # expect: fire
  - replay: benign/nat_gateway_morning_logins.jsonl   # expect: quiet
  - replay: benign/helpdesk_password_reset_wave.jsonl # expect: quiet
`

// EnsureConfigDirectory ensures default rule and test YAML exist on any new device.
// Checks current directory first; if not found, initializes ~/.cyberspring/ on the user's system.
func EnsureConfigDirectory() (rulePath string, testPath string) {
	// 1. Current working directory check
	localRule := filepath.Join("rules", "vpn_password_spray.yml")
	localTest := filepath.Join("tests", "vpn_password_spray_test.yml")
	if _, err := os.Stat(localRule); err == nil {
		return localRule, localTest
	}

	// 2. Fallback to standard User Config or Home Directory
	baseDir, err := os.UserConfigDir()
	if err != nil {
		baseDir, err = os.UserHomeDir()
		if err != nil {
			baseDir = "."
		}
	}

	appDir := filepath.Join(baseDir, "cyberspring")
	rulesDir := filepath.Join(appDir, "rules")
	testsDir := filepath.Join(appDir, "tests")

	_ = os.MkdirAll(rulesDir, 0755)
	_ = os.MkdirAll(testsDir, 0755)

	targetRule := filepath.Join(rulesDir, "vpn_password_spray.yml")
	targetTest := filepath.Join(testsDir, "vpn_password_spray_test.yml")

	if _, err := os.Stat(targetRule); os.IsNotExist(err) {
		_ = os.WriteFile(targetRule, []byte(DefaultRuleYAML), 0644)
	}

	if _, err := os.Stat(targetTest); os.IsNotExist(err) {
		_ = os.WriteFile(targetTest, []byte(DefaultTestYAML), 0644)
	}

	return targetRule, targetTest
}
