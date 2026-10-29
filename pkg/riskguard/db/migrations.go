package db

import (
	"database/sql"
	"fmt"
)

// Migration represents a versioned database schema migration.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

var migrations = []Migration{
	{
		Version: 1,
		Name:    "initial_riskguard_schema",
		SQL: `
		-- Schema version tracking
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);

		-- Global application configuration & preferences
		CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);

		-- IT Assets Inventory
		CREATE TABLE IF NOT EXISTS assets (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			hostname TEXT DEFAULT '',
			ip_address TEXT DEFAULT '',
			os_name TEXT DEFAULT '',
			os_version TEXT DEFAULT '',
			owner TEXT DEFAULT '',
			department TEXT DEFAULT '',
			environment TEXT DEFAULT 'Production',
			criticality TEXT DEFAULT 'Medium',
			data_sensitivity TEXT DEFAULT 'Internal',
			notes TEXT DEFAULT '',
			is_local_machine INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_assets_crit ON assets(criticality);
		CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);

		-- Managed & Local Endpoints Security Posture
		CREATE TABLE IF NOT EXISTS endpoints (
			id TEXT PRIMARY KEY,
			asset_id TEXT NOT NULL,
			device_name TEXT NOT NULL,
			os TEXT NOT NULL,
			os_version TEXT DEFAULT '',
			kernel TEXT DEFAULT '',
			arch TEXT DEFAULT '',
			firewall_status TEXT DEFAULT 'Unknown',
			encryption_status TEXT DEFAULT 'Unknown',
			antivirus_status TEXT DEFAULT 'Unknown',
			patch_status TEXT DEFAULT 'Unknown',
			posture_score INTEGER DEFAULT 0,
			status TEXT DEFAULT 'Online',
			last_checkin TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			software_json TEXT DEFAULT '[]',
			hardware_json TEXT DEFAULT '{}',
			FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_endpoints_asset ON endpoints(asset_id);
		CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status);

		-- Central Risk Register
		CREATE TABLE IF NOT EXISTS risks (
			id TEXT PRIMARY KEY,
			risk_code TEXT UNIQUE NOT NULL,
			title TEXT NOT NULL,
			description TEXT DEFAULT '',
			category TEXT NOT NULL,
			business_impact TEXT DEFAULT '',
			threat_scenario TEXT DEFAULT '',
			vulnerability_weakness TEXT DEFAULT '',
			affected_assets TEXT DEFAULT '',
			risk_owner TEXT DEFAULT '',
			likelihood INTEGER NOT NULL DEFAULT 3,
			impact INTEGER NOT NULL DEFAULT 3,
			inherent_score INTEGER NOT NULL DEFAULT 9,
			inherent_rating TEXT NOT NULL DEFAULT 'Medium',
			existing_controls TEXT DEFAULT '',
			residual_likelihood INTEGER NOT NULL DEFAULT 2,
			residual_impact INTEGER NOT NULL DEFAULT 2,
			residual_score INTEGER NOT NULL DEFAULT 4,
			residual_rating TEXT NOT NULL DEFAULT 'Low',
			treatment_strategy TEXT NOT NULL DEFAULT 'Mitigate',
			status TEXT NOT NULL DEFAULT 'Open',
			review_date TEXT DEFAULT '',
			justification TEXT DEFAULT '',
			approver TEXT DEFAULT '',
			approved_at TEXT DEFAULT '',
			is_sample INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_risks_status ON risks(status);
		CREATE INDEX IF NOT EXISTS idx_risks_rating ON risks(inherent_rating);
		CREATE INDEX IF NOT EXISTS idx_risks_score ON risks(inherent_score);

		-- Risk Mitigation Tasks
		CREATE TABLE IF NOT EXISTS mitigation_tasks (
			id TEXT PRIMARY KEY,
			risk_id TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT DEFAULT '',
			owner TEXT DEFAULT '',
			due_date TEXT DEFAULT '',
			status TEXT DEFAULT 'Not Started',
			completed_at TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(risk_id) REFERENCES risks(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_tasks_risk ON mitigation_tasks(risk_id);
		CREATE INDEX IF NOT EXISTS idx_tasks_status ON mitigation_tasks(status);

		-- Risk Assessment History & Audit
		CREATE TABLE IF NOT EXISTS risk_history (
			id TEXT PRIMARY KEY,
			risk_id TEXT NOT NULL,
			change_type TEXT NOT NULL,
			field_name TEXT NOT NULL,
			old_value TEXT DEFAULT '',
			new_value TEXT DEFAULT '',
			actor TEXT DEFAULT 'System',
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(risk_id) REFERENCES risks(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_history_risk ON risk_history(risk_id);

		-- Vulnerability Register
		CREATE TABLE IF NOT EXISTS vulnerabilities (
			id TEXT PRIMARY KEY,
			cve_id TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT DEFAULT '',
			severity TEXT NOT NULL DEFAULT 'Medium',
			cvss_score REAL DEFAULT 5.0,
			affected_software TEXT DEFAULT '',
			affected_asset_id TEXT DEFAULT '',
			linked_risk_id TEXT DEFAULT '',
			remediation_guidance TEXT DEFAULT '',
			owner TEXT DEFAULT '',
			due_date TEXT DEFAULT '',
			status TEXT DEFAULT 'Open',
			verified_at TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_vuln_sev ON vulnerabilities(severity);
		CREATE INDEX IF NOT EXISTS idx_vuln_status ON vulnerabilities(status);

		-- Central Alert Queue
		CREATE TABLE IF NOT EXISTS alerts (
			id TEXT PRIMARY KEY,
			title TEXT NOT NULL,
			description TEXT DEFAULT '',
			source TEXT NOT NULL DEFAULT 'Endpoint Telemetry',
			severity TEXT NOT NULL DEFAULT 'Medium',
			confidence TEXT NOT NULL DEFAULT 'High',
			evidence_json TEXT DEFAULT '{}',
			status TEXT NOT NULL DEFAULT 'New',
			affected_asset_id TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);

		-- Incident Response Queue
		CREATE TABLE IF NOT EXISTS incidents (
			id TEXT PRIMARY KEY,
			incident_code TEXT UNIQUE NOT NULL,
			title TEXT NOT NULL,
			description TEXT DEFAULT '',
			severity TEXT NOT NULL DEFAULT 'High',
			status TEXT NOT NULL DEFAULT 'Open',
			lead_investigator TEXT DEFAULT '',
			affected_asset_id TEXT DEFAULT '',
			linked_risk_id TEXT DEFAULT '',
			root_cause TEXT DEFAULT '',
			containment_action TEXT DEFAULT '',
			containment_status TEXT DEFAULT 'Pending',
			resolved_at TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_inc_status ON incidents(status);

		-- Incident Timeline Events
		CREATE TABLE IF NOT EXISTS incident_timeline (
			id TEXT PRIMARY KEY,
			incident_id TEXT NOT NULL,
			entry_type TEXT NOT NULL,
			description TEXT NOT NULL,
			actor TEXT DEFAULT 'Analyst',
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
		);

		-- Compliance Frameworks (ISO 27001, NIST CSF, CIS Controls, SOC 2)
		CREATE TABLE IF NOT EXISTS compliance_frameworks (
			id TEXT PRIMARY KEY,
			code TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL,
			version TEXT NOT NULL,
			description TEXT DEFAULT '',
			source TEXT DEFAULT ''
		);

		-- Control Register
		CREATE TABLE IF NOT EXISTS compliance_controls (
			id TEXT PRIMARY KEY,
			framework_id TEXT NOT NULL,
			control_id TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT DEFAULT '',
			category TEXT DEFAULT '',
			owner TEXT DEFAULT '',
			implementation_status TEXT DEFAULT 'Not Implemented',
			review_date TEXT DEFAULT '',
			gap_description TEXT DEFAULT '',
			corrective_action TEXT DEFAULT '',
			FOREIGN KEY(framework_id) REFERENCES compliance_frameworks(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_controls_fw ON compliance_controls(framework_id);

		-- Risk to Control Mappings
		CREATE TABLE IF NOT EXISTS risk_control_mappings (
			risk_id TEXT NOT NULL,
			control_id TEXT NOT NULL,
			mapped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(risk_id, control_id)
		);

		-- Evidence & Policies Repository
		CREATE TABLE IF NOT EXISTS evidence (
			id TEXT PRIMARY KEY,
			title TEXT NOT NULL,
			description TEXT DEFAULT '',
			file_name TEXT NOT NULL,
			file_path TEXT NOT NULL,
			file_size INTEGER DEFAULT 0,
			mime_type TEXT DEFAULT 'application/octet-stream',
			sha256_hash TEXT NOT NULL,
			entity_type TEXT DEFAULT 'General',
			entity_id TEXT DEFAULT '',
			uploaded_by TEXT DEFAULT 'User',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);

		-- Global Security Audit Trail
		CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			action TEXT NOT NULL,
			entity_type TEXT NOT NULL,
			entity_id TEXT NOT NULL,
			details TEXT DEFAULT '',
			actor TEXT DEFAULT 'User',
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp DESC);
		`,
	},
}

// RunMigrations executes pending database schema migrations in a transaction.
func RunMigrations(db *sql.DB) error {
	// 1. Ensure schema_migrations table exists
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	// 2. Iterate and apply migrations
	for _, m := range migrations {
		var exists int
		err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = ?", m.Version).Scan(&exists)
		if err != nil {
			return fmt.Errorf("failed to query migration status for v%d: %w", m.Version, err)
		}

		if exists == 0 {
			tx, err := db.Begin()
			if err != nil {
				return fmt.Errorf("failed to begin transaction for v%d: %w", m.Version, err)
			}

			if _, err := tx.Exec(m.SQL); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("failed to apply migration v%d (%s): %w", m.Version, m.Name, err)
			}

			if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES (?)", m.Version); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("failed to record migration v%d: %w", m.Version, err)
			}

			if err := tx.Commit(); err != nil {
				return fmt.Errorf("failed to commit migration v%d: %w", m.Version, err)
			}
		}
	}

	return nil
}
