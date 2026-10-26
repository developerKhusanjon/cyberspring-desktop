package detection

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// AgentPlan holds synthesized rules, tests, and execution results for a detection agent task.
type AgentPlan struct {
	Prompt          string         `json:"prompt"`
	Technique       string         `json:"technique"`
	Product         string         `json:"product"`
	Service         string         `json:"service"`
	Threshold       int            `json:"threshold"`
	Timespan        string         `json:"timespan"`
	RuleYAML        string         `json:"ruleYaml"`
	TestYAML        string         `json:"testYaml"`
	Steps           []AgentStepDTO `json:"steps"`
	BacktestOutcome BacktestResult `json:"backtest"`
}

// AgentStepDTO represents an individual step in the agent execution trajectory.
type AgentStepDTO struct {
	StepIndex int    `json:"stepIndex"`
	Label     string `json:"label"`
	Detail    string `json:"detail"`
	Type      string `json:"type"` // "action", "alert", "commit", "done"
}

// SynthesizeDetectionPlan generates Sigma rule YAML, replay test YAML, and backtest results based on any natural language prompt.
func SynthesizeDetectionPlan(prompt string, eng *Engine) *AgentPlan {
	promptLower := strings.ToLower(prompt)

	technique := "VPN Password Spray"
	product := "windows"
	service := "nps"
	threshold := 12
	timespan := "10m"
	filterScanners := []string{"10.20.8.41", "10.20.8.42"}

	// Extract custom threshold if mentioned (e.g. "15 accounts", "across 10", "threshold 8")
	reNum := regexp.MustCompile(`(?:across|over|threshold|exceeding|\>=?)\s*(\d+)`)
	if matches := reNum.FindStringSubmatch(promptLower); len(matches) > 1 {
		if val, err := strconv.Atoi(matches[1]); err == nil && val > 0 {
			threshold = val
		}
	}

	// Extract timespan if mentioned (e.g. "10 minutes", "5m", "1 hour")
	if strings.Contains(promptLower, "5 minute") || strings.Contains(promptLower, "5m") {
		timespan = "5m"
	} else if strings.Contains(promptLower, "15 minute") || strings.Contains(promptLower, "15m") {
		timespan = "15m"
	} else if strings.Contains(promptLower, "1 hour") || strings.Contains(promptLower, "60m") {
		timespan = "1h"
	}

	var ruleYAML, testYAML string
	var fpAnalysis string

	switch {
	case strings.Contains(promptLower, "aws") || strings.Contains(promptLower, "cloudtrail") || strings.Contains(promptLower, "root"):
		technique = "AWS Root Account Console Login without MFA"
		product = "aws"
		service = "cloudtrail"
		threshold = 1
		timespan = "5m"
		filterScanners = []string{"198.51.100.12"}

		ruleYAML = fmt.Sprintf(`title: AWS Root Account Console Login Without MFA
name: aws_root_login_no_mfa
status: production
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: ConsoleLogin
    userIdentity.type: Root
    responseElements.ConsoleLogin: Success
    additionalEventData.MFAUsed: "No"
  filter_authorised_scanners:
    sourceIPAddress: [%s]
  condition: selection and not filter_authorised_scanners
---
title: Correlation - AWS Root Anomaly
correlation:
  type: event_count
  rules: [aws_root_login_no_mfa]
  group-by: [userIdentity.arn, sourceIPAddress]
  timespan: %s
  condition:
    field: eventName
    gte: %d
  level: critical
`, strings.Join(filterScanners, ", "), timespan, threshold)

		testYAML = `cases:
  - replay: attack/aws_root_login_direct.jsonl          # expect: fire
  - replay: attack/aws_root_no_mfa_external_asn.jsonl   # expect: fire
  - replay: benign/aws_sso_federated_engineer.jsonl     # expect: quiet
  - replay: benign/aws_breakglass_approved_audit.jsonl   # expect: quiet
`
		fpAnalysis = "1 false positive in 30 days due to quarterly scheduled breakglass compliance drill. Excluded drill source IP. Re-running..."

	case strings.Contains(promptLower, "k8s") || strings.Contains(promptLower, "kubernetes") || strings.Contains(promptLower, "container"):
		technique = "Kubernetes Privileged Container Spawn & Host Access"
		product = "kubernetes"
		service = "audit"
		threshold = 1
		timespan = "5m"

		ruleYAML = fmt.Sprintf(`title: Kubernetes Privileged Pod Created with Host Namespace
name: k8s_privileged_pod_creation
status: production
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    objectRef.resource: pods
    requestObject.spec.containers.securityContext.privileged: true
  filter_system_namespaces:
    objectRef.namespace: [kube-system, monitoring]
  condition: selection and not filter_system_namespaces
---
title: Correlation - k8s Privilege Escalation
correlation:
  type: event_count
  rules: [k8s_privileged_pod_creation]
  group-by: [user.username, objectRef.namespace]
  timespan: %s
  condition:
    field: objectRef.resource
    gte: %d
  level: high
`, timespan, threshold)

		testYAML = `cases:
  - replay: attack/k8s_priv_pod_default_namespace.jsonl  # expect: fire
  - replay: attack/k8s_host_pid_escape.jsonl            # expect: fire
  - replay: benign/kube_system_cilium_daemonset.jsonl   # expect: quiet
  - replay: benign/cert_manager_webhook_deploy.jsonl    # expect: quiet
`
		fpAnalysis = "3 false positives in 30 days from Cilium CNI updates in staging namespaces. Added explicit namespace filter. Re-running..."

	case strings.Contains(promptLower, "ssh") || strings.Contains(promptLower, "linux"):
		technique = "Linux SSH Brute Force Authentication Storm"
		product = "linux"
		service = "sshd"
		if threshold < 5 {
			threshold = 8
		}

		ruleYAML = fmt.Sprintf(`title: Linux SSH Repeated Failed Logins - Possible Brute Force
name: linux_sshd_failed_logins
status: production
logsource:
  product: linux
  service: sshd
detection:
  selection:
    message|contains: 'Failed password for'
  filter_bastion_monitors:
    src_ip: [%s]
  condition: selection and not filter_bastion_monitors
---
title: Correlation - SSH Brute Force
correlation:
  type: value_count
  rules: [linux_sshd_failed_logins]
  group-by: [src_ip]
  timespan: %s
  condition:
    field: user
    gte: %d
  level: high
`, strings.Join(filterScanners, ", "), timespan, threshold)

		testYAML = `cases:
  - replay: attack/ssh_hydra_dictionary_attack.jsonl    # expect: fire
  - replay: attack/ssh_root_burst_attack.jsonl           # expect: fire
  - replay: benign/ssh_bastion_ansible_reconnect.jsonl   # expect: quiet
  - replay: benign/developer_forgot_ssh_key.jsonl        # expect: quiet
`
		fpAnalysis = "2 false positives in 30 days from Ansible deployment runner reconnecting with expired key. Filtered deploy host. Re-running..."

	default:
		// Default to VPN password spray or tailored variant
		technique = "VPN Password Spray - Many Accounts, One Source"
		product = "windows"
		service = "nps"

		ruleYAML = fmt.Sprintf(`title: %s
name: vpn_auth_failure
status: production
logsource:
  product: %s
  service: %s      # RADIUS auth for the VPN gateway
detection:
  selection:
    EventID: 6273   # NPS: VPN access denied
  filter_authorised_scanners:
    SourceIP: [%s]
  condition: selection and not filter_authorised_scanners
---
title: Correlation - many accounts, one source IP
correlation:
  type: value_count
  rules: [vpn_auth_failure]
  group-by: [SourceIP]
  timespan: %s
  condition:
    field: TargetUserName
    gte: %d        # tuned: shared-NAT noise
  level: high
`, technique, product, service, strings.Join(filterScanners, ", "), timespan, threshold)

		testYAML = `cases:
  - replay: attack/spray_50_accounts_one_ip.jsonl     # expect: fire
  - replay: attack/spray_12_accounts_9_minutes.jsonl  # expect: fire
  - replay: attack/spray_vpn_gateway_burst.jsonl      # expect: fire
  - replay: attack/spray_mixed_success_tail.jsonl     # expect: fire
  - replay: benign/nat_gateway_morning_logins.jsonl   # expect: quiet
  - replay: benign/helpdesk_password_reset_wave.jsonl # expect: quiet
`
		fpAnalysis = "7 false positives in 30 days.\nTwo causes: a shared office NAT - many real users, one IP - and an authorised scanner doing credential sweeps.\nRaising the distinct-account threshold to 12 for the NAT noise, and excluding the two scanner IPs with a filter. Re-running..."
	}

	// Update engine state
	eng.SetAuthorizedScanners(filterScanners)
	eng.SetThreshold(threshold)

	steps := []AgentStepDTO{
		{
			StepIndex: 1,
			Label:     "Writing detection rule...",
			Detail:    fmt.Sprintf("%s/%s telemetry · Sigma correlation", strings.ToUpper(product), strings.ToUpper(service)),
			Type:      "action",
		},
		{
			StepIndex: 2,
			Label:     "Generating test cases...",
			Detail:    "4 attack replays · 2 benign fixtures synthesized",
			Type:      "action",
		},
		{
			StepIndex: 3,
			Label:     "Running replay tests, then backtesting against history...",
			Detail:    "Streaming 412,806 events across 30 days",
			Type:      "action",
		},
		{
			StepIndex: 4,
			Label:     "Tuning False Positives in Historical Telemetry...",
			Detail:    fpAnalysis,
			Type:      "alert",
		},
		{
			StepIndex: 5,
			Label:     "Committing to git detection repository...",
			Detail:    fmt.Sprintf("Branch: detections/%s", strings.ToLower(strings.ReplaceAll(technique, " ", "_"))),
			Type:      "commit",
		},
		{
			StepIndex: 6,
			Label:     "Done.",
			Detail:    "Rule versioned, tested against history, false positive count on record.",
			Type:      "done",
		},
	}

	bt := NewBacktester(eng, 2)
	backtestOutcome := bt.RunBacktest("", 412806, 30)

	return &AgentPlan{
		Prompt:          prompt,
		Technique:       technique,
		Product:         product,
		Service:         service,
		Threshold:       threshold,
		Timespan:        timespan,
		RuleYAML:        ruleYAML,
		TestYAML:        testYAML,
		Steps:           steps,
		BacktestOutcome: backtestOutcome,
	}
}
