package soar

import (
	"fmt"
	"sync"
	"time"
)

// PlaybookStatus represents lifecycle states of automated SOAR playbooks.
type PlaybookStatus string

const (
	StatusRunning   PlaybookStatus = "Running"
	StatusCompleted PlaybookStatus = "Completed"
	StatusIdle      PlaybookStatus = "Idle"
	StatusFailed    PlaybookStatus = "Failed"
)

// Playbook defines an automated incident response workflow.
type Playbook struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Status      PlaybookStatus `json:"status"`
	ExecCount   int            `json:"execCount"`
	ActiveItems int            `json:"activeItems"`
	Target      string         `json:"target"`
	LastRun     time.Time      `json:"lastRun"`
	Logs        []string       `json:"logs"`
}

// Manager orchestrates and executes SOAR playbooks.
type Manager struct {
	mu        sync.RWMutex
	playbooks map[string]*Playbook
}

// NewManager initializes default playbooks matching reference UI.
func NewManager() *Manager {
	m := &Manager{
		playbooks: make(map[string]*Playbook),
	}

	// Image 3 Playbooks:
	m.playbooks["pb-malware"] = &Playbook{
		ID:          "pb-malware",
		Name:        "Malware Containment",
		Description: "Isolates infected host endpoint, terminates process trees, dumps memory snapshot to secure S3 bucket.",
		Status:      StatusCompleted,
		ExecCount:   12,
		ActiveItems: 0,
		Target:      "EDR / CrowdStrike & SentinelOne",
		LastRun:     time.Now().Add(-14 * time.Minute),
		Logs: []string{
			"Triggered by hash match on workstation WS-PROD-084",
			"Network interface severed (isolation mode activated)",
			"Process tree PID: 4892 terminated",
			"Forensic volatile memory dump completed",
			"Incident ticket SOC-8941 updated to Completed",
		},
	}

	m.playbooks["pb-ipblock"] = &Playbook{
		ID:          "pb-ipblock",
		Name:        "Suspicious IP Blocking",
		Description: "Pushes drop rules to edge Fortinet, Cisco ASA, and AWS WAF for IPs exhibiting brute-force/spray attacks.",
		Status:      StatusRunning,
		ExecCount:   48,
		ActiveItems: 5,
		Target:      "Perimeter WAF & Edge Firewalls",
		LastRun:     time.Now().Add(-2 * time.Minute),
		Logs: []string{
			"Detection correlation alert received: vpn_password_spray",
			"Blacklisting 185.220.101.5 on FortiGate-Edge-01",
			"Blacklisting 45.145.67.89 on Cisco-Firepower",
			"Applied AWS WAF rate-limiting rule on ALB ingress",
			"5 active blocks currently under dynamic TTL (60m)",
		},
	}

	m.playbooks["pb-okta"] = &Playbook{
		ID:          "pb-okta",
		Name:        "Okta Session Revocation & Step-Up",
		Description: "Terminates all active user browser sessions and enforces immediate biometric MFA challenge upon anomaly.",
		Status:      StatusCompleted,
		ExecCount:   8,
		ActiveItems: 0,
		Target:      "Identity Provider (Okta API)",
		LastRun:     time.Now().Add(-45 * time.Minute),
		Logs: []string{
			"Impossible travel alert for user robinson@enterprise.io",
			"Revoked 3 active OAuth refresh tokens",
			"Enforced step-up FIDO2 challenge",
		},
	}

	m.playbooks["pb-aws-quarantine"] = &Playbook{
		ID:          "pb-aws-quarantine",
		Name:        "AWS IAM Key Quarantine",
		Description: "Attaches explicit DenyAll boundary policy to compromised IAM user and invalidates STS temporary credentials.",
		Status:      StatusIdle,
		ExecCount:   3,
		ActiveItems: 0,
		Target:      "AWS IAM / SecurityTokenService",
		LastRun:     time.Now().Add(-3 * time.Hour),
		Logs: []string{
			"Compromised AKIA key detected in public pastebin feed",
			"Attached AWS DenyAll boundary policy",
			"STS temporary sessions invalidated",
		},
	}

	return m
}

// ListPlaybooks returns all registered automation playbooks.
func (m *Manager) ListPlaybooks() []*Playbook {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var list []*Playbook
	for _, pb := range m.playbooks {
		list = append(list, pb)
	}
	return list
}

// TriggerPlaybook executes a playbook by ID.
func (m *Manager) TriggerPlaybook(id string, targetParams string) (*Playbook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pb, ok := m.playbooks[id]
	if !ok {
		return nil, fmt.Errorf("playbook %s not found", id)
	}

	pb.Status = StatusRunning
	pb.ExecCount++
	pb.ActiveItems++
	pb.LastRun = time.Now()
	pb.Logs = append(pb.Logs, fmt.Sprintf("[%s] Executing against target: %s", time.Now().Format("15:04:05"), targetParams))

	// In real environment, runs asynchronously; here we simulate immediate successful action
	go func(targetPB *Playbook) {
		time.Sleep(2 * time.Second)
		m.mu.Lock()
		defer m.mu.Unlock()
		targetPB.Status = StatusCompleted
		if targetPB.ActiveItems > 0 {
			targetPB.ActiveItems--
		}
		targetPB.Logs = append(targetPB.Logs, fmt.Sprintf("[%s] Automated playbook steps completed successfully", time.Now().Format("15:04:05")))
	}(pb)

	return pb, nil
}
