package soar

import (
	"fmt"
	"sync"
)

// IntegrationFeed represents a connected cloud or network telemetry source.
type IntegrationFeed struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	EventCount int      `json:"eventCount"`
	Status     string   `json:"status"` // "healthy", "warning", "critical"
	HasWarning bool     `json:"hasWarning"`
	Icon       string   `json:"icon"`
	OrbitAngle int      `json:"orbitAngle"` // for radial canvas rendering
	OrbitTier  int      `json:"orbitTier"`  // 1 = inner, 2 = middle, 3 = outer
	RecentLogs []string `json:"recentLogs,omitempty"`
}

// Incident represents a security incident tracked in the controlling center.
type Incident struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"` // "High", "Medium", "Low"
	Source      string `json:"source"`
	Status      string `json:"status"` // "Open", "Triaged", "Contained", "Resolved"
	CreatedAt   string `json:"createdAt"`
	Description string `json:"description,omitempty"`
	Asset       string `json:"asset,omitempty"`
	AttackerIP  string `json:"attackerIP,omitempty"`
}

// SystemStatus holds the global SOC Controlling Center state matching Image 3.
type SystemStatus struct {
	ThreatsBlockedPercent int               `json:"threatsBlockedPercent"` // e.g. 68%
	OpenIncidentsTotal    int               `json:"openIncidentsTotal"`    // e.g. 7
	IncidentTrendPercent  int               `json:"incidentTrendPercent"`  // e.g. +35%
	HighSeverityCount     int               `json:"highSeverityCount"`     // 2
	MediumSeverityCount   int               `json:"mediumSeverityCount"`   // 2
	LowSeverityCount      int               `json:"lowSeverityCount"`      // 2
	ServersTotal          int               `json:"serversTotal"`          // 24
	ServersHealthy        int               `json:"serversHealthy"`        // 24
	WorkstationsTotal     int               `json:"workstationsTotal"`     // 38
	WorkstationsHealthy   int               `json:"workstationsHealthy"`   // 38
	AlertsHighTrend       int               `json:"alertsHighTrend"`       // +20%
	AlertsMediumTrend     int               `json:"alertsMediumTrend"`     // +8%
	Integrations          []IntegrationFeed `json:"integrations"`
	Incidents             []Incident        `json:"incidents"`
}

var (
	globalIncidentsMu sync.RWMutex
	globalIncidents   = []Incident{
		{
			ID:          "INC-4091",
			Title:       "VPN Password Spray Attack from External Subnet",
			Severity:    "High",
			Source:      "Fortinet / Windows NPS",
			Status:      "Open",
			CreatedAt:   "10m ago",
			Description: "14 authentication failures across distinct user accounts originating from external IP 45.145.67.89 within 9 minutes.",
			Asset:       "VPN Gateway (gw-ext-01.corp)",
			AttackerIP:  "45.145.67.89",
		},
		{
			ID:          "INC-4089",
			Title:       "AWS Root Account Console Login without MFA",
			Severity:    "High",
			Source:      "AWS CloudTrail",
			Status:      "Open",
			CreatedAt:   "34m ago",
			Description: "Root console login detected without multi-factor authentication from unusual ISP/ASN in Eastern Europe.",
			Asset:       "AWS Root (Account 982341094812)",
			AttackerIP:  "185.220.101.5",
		},
		{
			ID:          "INC-4084",
			Title:       "Unusual Outbound Data Egress to Uncategorized IP",
			Severity:    "Medium",
			Source:      "Cisco Firepower",
			Status:      "Triaged",
			CreatedAt:   "1h 15m ago",
			Description: "High-volume encrypted TLS session initiated from workstation WS-PROD-084 to uncategorized IP on port 8443.",
			Asset:       "WS-PROD-084 (Windows 11)",
			AttackerIP:  "91.240.118.17",
		},
		{
			ID:          "INC-4078",
			Title:       "GitHub Repository Secret Scan Finding: AWS Access Key",
			Severity:    "Medium",
			Source:      "GitHub Advanced Security",
			Status:      "Triaged",
			CreatedAt:   "2h ago",
			Description: "Hardcoded AWS Access Key ID (AKIA...) committed to repository test_samples/vulnerable_app/cloud_storage.py.",
			Asset:       "git://corp/backend-services.git",
			AttackerIP:  "Internal Commit",
		},
		{
			ID:          "INC-4072",
			Title:       "Okta Impossible Travel: US to Netherlands within 12m",
			Severity:    "Low",
			Source:      "Okta SystemLog",
			Status:      "Contained",
			CreatedAt:   "3h ago",
			Description: "User session authenticated from San Francisco (US) followed 12 minutes later by logon from Amsterdam (NL).",
			Asset:       "robinson@enterprise.io",
			AttackerIP:  "194.26.29.112",
		},
		{
			ID:          "INC-4068",
			Title:       "Multiple Expired TLS Certificates on Internal Ingress",
			Severity:    "Low",
			Source:      "Azure App Gateway",
			Status:      "Contained",
			CreatedAt:   "5h ago",
			Description: "Internal wildcard TLS certificate *.stage.internal expired 48 hours ago.",
			Asset:       "Azure Application Gateway",
			AttackerIP:  "N/A",
		},
	}
)

// UpdateIncidentStatus modifies an incident state (Open, Triaged, Contained, Resolved).
func UpdateIncidentStatus(id string, newStatus string) (*Incident, error) {
	globalIncidentsMu.Lock()
	defer globalIncidentsMu.Unlock()

	for i := range globalIncidents {
		if globalIncidents[i].ID == id {
			globalIncidents[i].Status = newStatus
			return &globalIncidents[i], nil
		}
	}
	return nil, fmt.Errorf("incident %s not found", id)
}

// GetSystemStatus returns the current live telemetry state modeled directly from Image 3.
func GetSystemStatus() SystemStatus {
	globalIncidentsMu.RLock()
	incidentsCopy := make([]Incident, len(globalIncidents))
	copy(incidentsCopy, globalIncidents)
	globalIncidentsMu.RUnlock()

	var openTotal, critCount, highCount, medCount, lowCount int
	for _, inc := range incidentsCopy {
		if inc.Status == "Open" || inc.Status == "Triaged" {
			openTotal++
			switch inc.Severity {
			case "Critical":
				critCount++
			case "High":
				highCount++
			case "Medium":
				medCount++
			case "Low":
				lowCount++
			}
		}
	}

	return SystemStatus{
		ThreatsBlockedPercent: 68,
		OpenIncidentsTotal:    openTotal,
		IncidentTrendPercent:  35,
		HighSeverityCount:     highCount + critCount,
		MediumSeverityCount:   medCount,
		LowSeverityCount:      lowCount,
		ServersTotal:          24,
		ServersHealthy:        24,
		WorkstationsTotal:     38,
		WorkstationsHealthy:   38,
		AlertsHighTrend:       20,
		AlertsMediumTrend:     8,
		Integrations: []IntegrationFeed{
			{
				ID:         "okta",
				Name:       "Okta",
				Category:   "Identity & SSO",
				EventCount: 12,
				Status:     "healthy",
				HasWarning: false,
				Icon:       "okta",
				OrbitAngle: 150,
				OrbitTier:  2,
				RecentLogs: []string{
					"15:32:01 · robinson@enterprise.io session refreshed (FIDO2 MFA verified)",
					"15:28:44 · admin_svc OAuth token rotated successfully",
					"15:15:10 · 0 lockouts in past 60 minutes",
				},
			},
			{
				ID:         "azure",
				Name:       "Microsoft Azure",
				Category:   "Cloud Telemetry",
				EventCount: 18,
				Status:     "healthy",
				HasWarning: false,
				Icon:       "azure",
				OrbitAngle: 125,
				OrbitTier:  3,
				RecentLogs: []string{
					"15:34:12 · Azure Defender: Zero critical security posture alerts",
					"15:20:05 · AppGateway ingress: 2,410 req/s normal traffic",
					"15:11:40 · Sentinel ingestion latency 82ms",
				},
			},
			{
				ID:         "aws",
				Name:       "AWS",
				Category:   "Cloud Telemetry",
				EventCount: 32,
				Status:     "healthy",
				HasWarning: false,
				Icon:       "aws",
				OrbitAngle: 80,
				OrbitTier:  3,
				RecentLogs: []string{
					"15:33:55 · GuardDuty: DNS request anomaly triaged as benign",
					"15:29:10 · WAF rule block: 42 SQLi probes dropped at CloudFront",
					"15:24:02 · IAM Access Analyzer: No public S3 bucket exposures",
				},
			},
			{
				ID:         "gcp",
				Name:       "Google Cloud",
				Category:   "Cloud Telemetry",
				EventCount: 14,
				Status:     "healthy",
				HasWarning: false,
				Icon:       "gcp",
				OrbitAngle: 55,
				OrbitTier:  2,
				RecentLogs: []string{
					"15:31:00 · Cloud Armor rate limit applied on /api/login endpoint",
					"15:18:22 · GKE cluster node pool health check: all pods healthy",
				},
			},
			{
				ID:         "github",
				Name:       "GitHub",
				Category:   "Code / CI Security",
				EventCount: 9,
				Status:     "healthy",
				HasWarning: false,
				Icon:       "github",
				OrbitAngle: 30,
				OrbitTier:  2,
				RecentLogs: []string{
					"15:30:15 · Dependabot audit completed across 4 repositories",
					"15:22:40 · Secret scan push-protection intercepted 1 dummy test key",
				},
			},
			{
				ID:         "fortinet",
				Name:       "Fortinet",
				Category:   "Perimeter Firewall",
				EventCount: 7,
				Status:     "warning",
				HasWarning: true,
				Icon:       "fortinet",
				OrbitAngle: 175,
				OrbitTier:  1,
				RecentLogs: []string{
					"15:35:01 · [ALERT] Port scanning probe dropped from 45.145.67.89",
					"15:34:20 · VPN Auth denial rate spiked 300% on external gateway",
					"15:32:08 · Dynamic IPS signature IPS-1849 active",
				},
			},
			{
				ID:         "cisco",
				Name:       "Cisco",
				Category:   "Network Switch / VPN",
				EventCount: 6,
				Status:     "warning",
				HasWarning: true,
				Icon:       "cisco",
				OrbitAngle: 5,
				OrbitTier:  1,
				RecentLogs: []string{
					"15:34:50 · [WARNING] RADIUS authentication retries exceeded on gateway switch",
					"15:33:14 · ACL drop count: 814 packets in 5m window",
				},
			},
		},
		Incidents: incidentsCopy,
	}
}
