package db

import (
	"database/sql"
	"fmt"
	"time"
)

// SeedInitialData populates default settings and compliance control catalogs.
// If withSampleData is true, it also inserts a realistic demonstration workspace.
func SeedInitialData(db *sql.DB, withSampleData bool) error {
	// 1. Default Settings
	defaults := map[string]string{
		"product_name":            "RiskGuard Desktop",
		"scoring_model":           "likelihood_x_impact",
		"risk_appetite_threshold": "12",
		"theme":                   "dark",
		"organization_name":       "Enterprise Security Operations",
		"workspace_mode":          "sample",
	}
	if !withSampleData {
		defaults["workspace_mode"] = "production"
	}

	for k, v := range defaults {
		_, err := db.Exec("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", k, v)
		if err != nil {
			return fmt.Errorf("failed to seed setting %s: %w", k, err)
		}
	}

	// 2. Compliance Frameworks
	frameworks := []struct {
		id, code, name, version, desc, src string
	}{
		{"fw_iso27001", "ISO-27001", "ISO/IEC 27001", "2022", "Information security management systems requirements", "International Organization for Standardization"},
		{"fw_nist_csf", "NIST-CSF", "NIST Cybersecurity Framework", "2.0", "Core taxonomy of cybersecurity outcomes across Govern, Identify, Protect, Detect, Respond, Recover", "National Institute of Standards and Technology"},
		{"fw_cis_v8", "CIS-Controls", "CIS Critical Security Controls", "v8.0", "Prioritized set of actions that protect organizations and data from cyber attacks", "Center for Internet Security"},
		{"fw_soc2", "SOC-2", "AICPA Trust Services Criteria (SOC 2)", "2017", "Criteria for Security, Availability, Processing Integrity, and Confidentiality", "AICPA"},
	}

	for _, f := range frameworks {
		_, err := db.Exec(`INSERT OR IGNORE INTO compliance_frameworks (id, code, name, version, description, source) VALUES (?, ?, ?, ?, ?, ?)`,
			f.id, f.code, f.name, f.version, f.desc, f.src)
		if err != nil {
			return fmt.Errorf("failed to seed framework %s: %w", f.code, err)
		}
	}

	// 3. Core Compliance Controls
	controls := []struct {
		id, fwID, cID, title, desc, cat, owner, status string
	}{
		// ISO 27001
		{"ctrl_iso_5_1", "fw_iso27001", "A.5.1", "Policies for Information Security", "Information security policy and topic-specific policies must be defined and reviewed.", "Organizational", "CISO", "Implemented"},
		{"ctrl_iso_8_8", "fw_iso27001", "A.8.8", "Management of Technical Vulnerabilities", "Information about technical vulnerabilities of information systems being used must be obtained, exposure evaluated and appropriate measures taken.", "Technological", "SecOps Lead", "Partially Implemented"},
		{"ctrl_iso_8_20", "fw_iso27001", "A.8.20", "Network Security Controls", "Networks and network devices shall be secured, managed and controlled to protect information.", "Technological", "Network Admin", "Implemented"},
		{"ctrl_iso_8_24", "fw_iso27001", "A.8.24", "Use of Cryptography", "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.", "Technological", "Security Architect", "Implemented"},
		{"ctrl_iso_8_7", "fw_iso27001", "A.8.7", "Protection Against Malware", "Protection against malware shall be implemented and supported by appropriate user awareness.", "Technological", "Endpoint Admin", "Implemented"},

		// NIST CSF 2.0
		{"ctrl_nist_id_am", "fw_nist_csf", "ID.AM-01", "Physical and Virtual Asset Inventory", "Inventories of hardware and software platforms managed within the organization are maintained.", "Identify", "IT Asset Manager", "Implemented"},
		{"ctrl_nist_pr_ds", "fw_nist_csf", "PR.DS-01", "Data-at-Rest Protection", "Data-at-rest is protected using authenticated encryption and access restrictions.", "Protect", "Security Architect", "Implemented"},
		{"ctrl_nist_de_cm", "fw_nist_csf", "DE.CM-01", "Continuous Telemetry Monitoring", "Networks and systems are monitored to discover potential cybersecurity events and posture drift.", "Detect", "SOC Team", "Partially Implemented"},
		{"ctrl_nist_rs_ma", "fw_nist_csf", "RS.MA-01", "Incident Containment & Mitigation", "Incidents are contained and mitigated to prevent further spread and damage.", "Respond", "Incident Commander", "Implemented"},

		// CIS Controls v8
		{"ctrl_cis_1_1", "fw_cis_v8", "CIS-1.1", "Enterprise Asset Inventory", "Actively manage (inventory, track, and correct) all enterprise assets connected to infrastructure.", "Asset Inventory", "IT Operations", "Implemented"},
		{"ctrl_cis_4_1", "fw_cis_v8", "CIS-4.1", "Secure Configuration Baseline", "Establish and maintain a secure configuration process for enterprise assets and software.", "Configuration", "System Engineer", "Partially Implemented"},
		{"ctrl_cis_7_1", "fw_cis_v8", "CIS-7.1", "Vulnerability Management Process", "Establish and maintain a documented vulnerability management process for enterprise assets.", "Vulnerability", "SecOps Lead", "Partially Implemented"},
		{"ctrl_cis_10_1", "fw_cis_v8", "CIS-10.1", "Deploy Anti-Malware Software", "Deploy and maintain anti-malware software on all enterprise assets.", "Protection", "Endpoint Admin", "Implemented"},

		// SOC 2
		{"ctrl_soc_cc6_1", "fw_soc2", "CC6.1", "Logical Access Security", "The entity implements logical access security software, infrastructure, and architectures.", "Security", "IAM Team", "Implemented"},
		{"ctrl_soc_cc6_6", "fw_soc2", "CC6.6", "Boundary Protection & Firewalls", "The entity implements logical boundaries and network firewalls to restrict unauthorized traffic.", "Security", "Network Team", "Implemented"},
		{"ctrl_soc_cc7_1", "fw_soc2", "CC7.1", "Vulnerability Monitoring & Pen Testing", "To meet its objectives, the entity uses detection and monitoring procedures to identify changes in vulnerability.", "Security", "SecOps Lead", "Partially Implemented"},
	}

	for _, c := range controls {
		_, err := db.Exec(`INSERT OR IGNORE INTO compliance_controls (id, framework_id, control_id, title, description, category, owner, implementation_status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			c.id, c.fwID, c.cID, c.title, c.desc, c.cat, c.owner, c.status)
		if err != nil {
			return fmt.Errorf("failed to seed control %s: %w", c.cID, err)
		}
	}

	if withSampleData {
		return SeedSampleWorkspace(db)
	}
	return nil
}

// SeedSampleWorkspace inserts realistic demonstration records.
func SeedSampleWorkspace(db *sql.DB) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	reviewDate := time.Now().AddDate(0, 3, 0).Format("2006-01-02")
	dueSoon := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	overdueDate := time.Now().AddDate(0, 0, -3).Format("2006-01-02")

	// 1. Assets
	assets := []struct {
		id, name, aType, host, ip, osName, osVer, owner, dept, env, crit, sens, notes string
		isLocal                                                                       int
	}{
		{"ast_db_01", "Production Database Cluster (Primary)", "Server", "db-prod-01.internal", "10.0.12.50", "Ubuntu Linux", "22.04 LTS", "Sarah Jenkins", "Data Operations", "Production", "Critical", "Confidential", "Hosts primary customer transactional records and encrypted credentials.", 0},
		{"ast_mac_01", "Security Engineering Workstation", "Computer", "seclab-mbp16.local", "10.20.4.15", "macOS", "Sonoma 14.5", "Alex Rivera", "Information Security", "Production", "High", "Restricted", "Authorized for SOC investigation, cloud bastion access, and key signing.", 1},
		{"ast_vpn_01", "Corporate Edge VPN Gateway", "Network", "vpn-gw01.corp.net", "198.51.100.25", "FortiOS", "7.4.2", "Mark Miller", "Network Engineering", "Production", "Critical", "Restricted", "Primary remote access gateway for global engineering workforce.", 0},
		{"ast_k8s_01", "AWS EKS Production Cluster", "Cloud", "eks-prod-us-east-1", "172.31.0.10", "Amazon Linux", "2023", "DevOps Team", "Platform Engineering", "Production", "Critical", "Confidential", "Kubernetes cluster hosting public web applications and API microservices.", 0},
	}

	for _, a := range assets {
		_, err := db.Exec(`INSERT OR REPLACE INTO assets 
			(id, name, type, hostname, ip_address, os_name, os_version, owner, department, environment, criticality, data_sensitivity, notes, is_local_machine, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			a.id, a.name, a.aType, a.host, a.ip, a.osName, a.osVer, a.owner, a.dept, a.env, a.crit, a.sens, a.notes, a.isLocal, now)
		if err != nil {
			return err
		}
	}

	// 2. Endpoints
	endpoints := []struct {
		id, astID, devName, os, osVer, arch, fw, enc, av, patch string
		score                                                   int
		status                                                  string
	}{
		{"ep_mac_01", "ast_mac_01", "seclab-mbp16", "macOS", "14.5 (23F79)", "arm64", "Pass", "Pass", "Pass", "Pass", 98, "Online"},
		{"ep_db_01", "ast_db_01", "db-prod-01", "Linux", "5.15.0-generic", "x86_64", "Pass", "Pass", "Fail", "Fail", 62, "Unhealthy"},
	}

	for _, ep := range endpoints {
		_, err := db.Exec(`INSERT OR REPLACE INTO endpoints 
			(id, asset_id, device_name, os, os_version, arch, firewall_status, encryption_status, antivirus_status, patch_status, posture_score, status, last_checkin)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			ep.id, ep.astID, ep.devName, ep.os, ep.osVer, ep.arch, ep.fw, ep.enc, ep.av, ep.patch, ep.score, ep.status, now)
		if err != nil {
			return err
		}
	}

	// 3. Risks
	risks := []struct {
		id, code, title, desc, cat, impact, threat, vuln, assets, owner string
		lh, imp, inhScore                                               int
		inhRating, controls                                             string
		resLh, resImp, resScore                                         int
		resRating, treat, status, just, appBy                           string
	}{
		{
			"rsk_101", "RSK-101",
			"Remote Code Execution on Unpatched Production Database Host",
			"Open critical CVEs on production database nodes could allow an adversary to execute arbitrary system commands, bypass access controls, and extract customer records.",
			"Technical Security",
			"Direct compromise of customer personally identifiable information (PII) leading to regulatory fines (GDPR/CCPA) and severe operational outage.",
			"External threat actor leverages known public exploit against internet-reachable services.",
			"Delayed security kernel patches on Ubuntu 22.04 LTS database hosts.",
			"Production Database Cluster (Primary)", "Sarah Jenkins",
			4, 5, 20, "Critical", "Host-based firewall enabled, perimeter VPC isolation.",
			2, 3, 6, "Low", "Mitigate", "Open", "", "",
		},
		{
			"rsk_102", "RSK-102",
			"VPN Credential Stuffing & Password Spray Attacks",
			"High frequency of unauthorized VPN authentication failures originating from foreign residential proxies targeting Active Directory accounts.",
			"Identity & Access",
			"Unauthorized network access leading to lateral movement across internal corporate subnets.",
			"Organized ransomware gang conducting password spray campaigns against staff credentials.",
			"Missing conditional access / geographic geofencing on RADIUS VPN gateway.",
			"Corporate Edge VPN Gateway", "Mark Miller",
			4, 4, 16, "High", "RADIUS authentication logs monitored in SIEM.",
			2, 2, 4, "Low", "Mitigate", "Open", "", "",
		},
		{
			"rsk_103", "RSK-103",
			"Cloud Storage Bucket Misconfiguration Leading to Public Data Leak",
			"Accidental removal of block public access settings on S3 buckets containing database backups or analytics dumps.",
			"Cloud Security",
			"Public exposure of corporate backups and compliance audit failure.",
			"Privileged developer accidentally alters IAM bucket policy during deployment.",
			"Manual bucket policy creation without automated CI/CD policy linting.",
			"AWS EKS Production Cluster", "DevOps Team",
			2, 5, 10, "Medium", "AWS GuardDuty and AWS Config enabled.",
			1, 3, 3, "Low", "Mitigate", "Under Review", "", "",
		},
		{
			"rsk_104", "RSK-104",
			"Legacy Isolated Development Workstation Missing Endpoint Sensor",
			"Development machine used for hardware simulation lacks modern EDR sensor due to kernel compatibility constraints.",
			"Endpoint Security",
			"Localized infection of development workstation with malware.",
			"Infected USB drive or untrusted third-party software binary.",
			"Legacy OS cannot run enterprise EDR agent.",
			"Security Engineering Workstation", "Alex Rivera",
			3, 2, 6, "Low", "Air-gapped VLAN, USB mass storage disabled via OS policy.",
			2, 2, 4, "Low", "Accept", "Accepted",
			"Device is isolated on non-routed VLAN 409 and has no access to production infrastructure or secrets.",
			"Alex Rivera (CISO)",
		},
	}

	for _, r := range risks {
		_, err := db.Exec(`INSERT OR REPLACE INTO risks 
			(id, risk_code, title, description, category, business_impact, threat_scenario, vulnerability_weakness,
			 affected_assets, risk_owner, likelihood, impact, inherent_score, inherent_rating, existing_controls,
			 residual_likelihood, residual_impact, residual_score, residual_rating, treatment_strategy, status,
			 review_date, justification, approver, approved_at, is_sample, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
			r.id, r.code, r.title, r.desc, r.cat, r.impact, r.threat, r.vuln,
			r.assets, r.owner, r.lh, r.imp, r.inhScore, r.inhRating, r.controls,
			r.resLh, r.resImp, r.resScore, r.resRating, r.treat, r.status,
			reviewDate, r.just, r.appBy, now, now)
		if err != nil {
			return err
		}
	}

	// 4. Mitigation Tasks
	tasks := []struct {
		id, rID, title, desc, owner, due, status string
	}{
		{"tsk_01", "rsk_101", "Apply Emergency Linux Kernel Security Patch", "Schedule maintenance window and update Linux kernel packages to 5.15.0-112.", "Sarah Jenkins", overdueDate, "Overdue"},
		{"tsk_02", "rsk_101", "Install ClamAV & EDR Sensor on Database Host", "Deploy and verify endpoint security protection daemon.", "SecOps Lead", dueSoon, "In Progress"},
		{"tsk_03", "rsk_102", "Enforce Strict FIDO2 / MFA on VPN Gateway", "Upgrade Fortinet RADIUS authentication to require mandatory WebAuthn MFA.", "Mark Miller", dueSoon, "In Progress"},
		{"tsk_04", "rsk_103", "Enable Automated AWS SCP S3 Block Public Access", "Apply organization-wide Service Control Policy preventing public S3 bucket creation.", "DevOps Team", dueSoon, "Not Started"},
	}

	for _, t := range tasks {
		_, err := db.Exec(`INSERT OR REPLACE INTO mitigation_tasks 
			(id, risk_id, title, description, owner, due_date, status)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			t.id, t.rID, t.title, t.desc, t.owner, t.due, t.status)
		if err != nil {
			return err
		}
	}

	// 5. Vulnerabilities
	vulns := []struct {
		id, cve, title, desc, sev                   string
		cvss                                        float64
		soft, astID, rID, guide, owner, due, status string
	}{
		{
			"vuln_01", "CVE-2024-38077",
			"Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability",
			"An unauthenticated attacker could send specially crafted packets to an affected RDP licensing service to execute arbitrary code with SYSTEM privileges.",
			"Critical", 9.8,
			"Windows Server RDP Licensing", "ast_db_01", "rsk_101",
			"Apply Microsoft Security Update KB5040442 immediately or disable RDP licensing port 135/3389.",
			"Sarah Jenkins", overdueDate, "Open",
		},
		{
			"vuln_02", "CVE-2024-21413",
			"Microsoft Outlook Remote Code Execution Vulnerability (Moniker Link)",
			"Bypasses Protected View and opens malicious Office files in editing mode via file:// URLs in Outlook messages.",
			"High", 8.5,
			"Microsoft 365 Outlook < 16.0.17328", "ast_mac_01", "",
			"Update Microsoft 365 Apps to Version 2402 (Build 17328.20162) or later.",
			"IT Support", dueSoon, "In Progress",
		},
		{
			"vuln_03", "CVE-2023-48795",
			"Terrapin Attack: SSH Protocol Prefix Truncation Vulnerability",
			"A man-in-the-middle attacker can truncate messages between client and server during SSH key exchange without being detected.",
			"Medium", 5.9,
			"OpenSSH < 9.6p1", "ast_vpn_01", "rsk_102",
			"Upgrade OpenSSH to 9.6p1 or disable ChaCha20-Poly1305 and CBC ciphers with ETM.",
			"Mark Miller", dueSoon, "Open",
		},
	}

	for _, v := range vulns {
		_, err := db.Exec(`INSERT OR REPLACE INTO vulnerabilities 
			(id, cve_id, title, description, severity, cvss_score, affected_software, affected_asset_id, linked_risk_id, remediation_guidance, owner, due_date, status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			v.id, v.cve, v.title, v.desc, v.sev, v.cvss, v.soft, v.astID, v.rID, v.guide, v.owner, v.due, v.status)
		if err != nil {
			return err
		}
	}

	// 6. Incidents
	incidents := []struct {
		id, code, title, desc, sev, status, lead, astID, rID, root, act, actStat string
	}{
		{
			"inc_01", "INC-2026-001",
			"Multiple VPN Authentication Failures from External Bulletproof Host",
			"RADIUS telemetry flagged 54 failed authentication attempts across 14 distinct engineering usernames originating from single source IP 198.51.100.84.",
			"High", "Investigating", "Alex Rivera", "ast_vpn_01", "rsk_102",
			"External automated credential spray campaign against VPN RADIUS gateway.",
			"Drop source IP at border firewall & reset targeted user sessions.", "Confirmed",
		},
		{
			"inc_02", "INC-2026-002",
			"Unencrypted Mass Storage Device Mounted on Security Workstation",
			"USB audit daemon detected 128GB flash drive with unverified FAT32 partition mounted without BitLocker/FileVault encryption.",
			"Medium", "Resolved", "SecOps Analyst", "ast_mac_01", "rsk_104",
			"Staff member attempted manual file backup to personal drive.",
			"Ejected storage device and reminded user of enterprise removable media policy.", "Confirmed",
		},
	}

	for _, inc := range incidents {
		_, err := db.Exec(`INSERT OR REPLACE INTO incidents 
			(id, incident_code, title, description, severity, status, lead_investigator, affected_asset_id, linked_risk_id, root_cause, containment_action, containment_status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			inc.id, inc.code, inc.title, inc.desc, inc.sev, inc.status, inc.lead, inc.astID, inc.rID, inc.root, inc.act, inc.actStat)
		if err != nil {
			return err
		}
	}

	// 7. Map Risks to Controls (The Core Differentiator!)
	mappings := []struct{ rID, cID string }{
		{"rsk_101", "ctrl_iso_8_8"},
		{"rsk_101", "ctrl_cis_7_1"},
		{"rsk_102", "ctrl_iso_8_20"},
		{"rsk_102", "ctrl_soc_cc6_1"},
		{"rsk_103", "ctrl_nist_pr_ds"},
		{"rsk_104", "ctrl_cis_10_1"},
	}

	for _, m := range mappings {
		_, _ = db.Exec(`INSERT OR IGNORE INTO risk_control_mappings (risk_id, control_id) VALUES (?, ?)`, m.rID, m.cID)
	}

	return nil
}

// ClearSampleWorkspace wipes sample demonstration records leaving schema and frameworks intact.
func ClearSampleWorkspace(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tables := []string{
		"DELETE FROM mitigation_tasks WHERE risk_id IN (SELECT id FROM risks WHERE is_sample = 1)",
		"DELETE FROM risk_history WHERE risk_id IN (SELECT id FROM risks WHERE is_sample = 1)",
		"DELETE FROM risk_control_mappings WHERE risk_id IN (SELECT id FROM risks WHERE is_sample = 1)",
		"DELETE FROM risks WHERE is_sample = 1",
		"DELETE FROM vulnerabilities WHERE affected_asset_id LIKE 'ast_%'",
		"DELETE FROM incidents WHERE id LIKE 'inc_%'",
		"DELETE FROM endpoints WHERE id LIKE 'ep_%'",
		"DELETE FROM assets WHERE id LIKE 'ast_%'",
	}

	for _, q := range tables {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}

	_, _ = tx.Exec("UPDATE settings SET value = 'production' WHERE key = 'workspace_mode'")

	return tx.Commit()
}
