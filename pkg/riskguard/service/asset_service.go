package service

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"cyberspring/pkg/riskguard/models"
)

// AssetService manages IT asset inventory and relationships.
type AssetService struct {
	db *sql.DB
}

// NewAssetService creates an AssetService.
func NewAssetService(db *sql.DB) *AssetService {
	return &AssetService{db: db}
}

// ListAssets returns all assets with linked counts for risks, vulnerabilities, and incidents.
func (s *AssetService) ListAssets(assetType, criticality, query string) ([]models.Asset, error) {
	var conditions []string
	var args []interface{}

	if assetType != "" && assetType != "All" {
		conditions = append(conditions, "type = ?")
		args = append(args, assetType)
	}
	if criticality != "" && criticality != "All" {
		conditions = append(conditions, "criticality = ?")
		args = append(args, criticality)
	}
	if query != "" {
		like := "%" + query + "%"
		conditions = append(conditions, "(name LIKE ? OR hostname LIKE ? OR ip_address LIKE ? OR owner LIKE ?)")
		args = append(args, like, like, like, like)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	querySQL := fmt.Sprintf(`
		SELECT a.id, a.name, a.type, a.hostname, a.ip_address, a.os_name, a.os_version,
		       a.owner, a.department, a.environment, a.criticality, a.data_sensitivity,
		       a.notes, a.is_local_machine, a.created_at, a.updated_at,
		       (SELECT COUNT(*) FROM vulnerabilities v WHERE v.affected_asset_id = a.id) as vuln_cnt,
		       (SELECT COUNT(*) FROM incidents i WHERE i.affected_asset_id = a.id) as inc_cnt
		FROM assets a
		%s
		ORDER BY 
			CASE a.criticality 
				WHEN 'Critical' THEN 1 
				WHEN 'High' THEN 2 
				WHEN 'Medium' THEN 3 
				ELSE 4 
			END, a.name ASC
	`, whereClause)

	rows, err := s.db.Query(querySQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.Asset
	for rows.Next() {
		var a models.Asset
		var isLocal int
		err := rows.Scan(
			&a.ID, &a.Name, &a.Type, &a.Hostname, &a.IPAddress, &a.OSName, &a.OSVersion,
			&a.Owner, &a.Department, &a.Environment, &a.Criticality, &a.DataSensitivity,
			&a.Notes, &isLocal, &a.CreatedAt, &a.UpdatedAt, &a.LinkedVulns, &a.LinkedIncidents,
		)
		if err == nil {
			a.IsLocalMachine = isLocal == 1
			results = append(results, a)
		}
	}
	return results, nil
}

// CreateAsset creates a new asset record.
func (s *AssetService) CreateAsset(a *models.Asset) error {
	if a.ID == "" {
		a.ID = fmt.Sprintf("ast_%d", time.Now().UnixNano())
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	a.CreatedAt = now
	a.UpdatedAt = now

	_, err := s.db.Exec(`
		INSERT INTO assets 
		(id, name, type, hostname, ip_address, os_name, os_version, owner, department,
		 environment, criticality, data_sensitivity, notes, is_local_machine, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
	`,
		a.ID, a.Name, a.Type, a.Hostname, a.IPAddress, a.OSName, a.OSVersion, a.Owner,
		a.Department, a.Environment, a.Criticality, a.DataSensitivity, a.Notes, a.CreatedAt, a.UpdatedAt,
	)
	return err
}

// UpdateAsset updates an existing asset.
func (s *AssetService) UpdateAsset(a *models.Asset) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	a.UpdatedAt = now

	_, err := s.db.Exec(`
		UPDATE assets SET
			name = ?, type = ?, hostname = ?, ip_address = ?, os_name = ?,
			os_version = ?, owner = ?, department = ?, environment = ?,
			criticality = ?, data_sensitivity = ?, notes = ?, updated_at = ?
		WHERE id = ?
	`,
		a.Name, a.Type, a.Hostname, a.IPAddress, a.OSName,
		a.OSVersion, a.Owner, a.Department, a.Environment,
		a.Criticality, a.DataSensitivity, a.Notes, a.UpdatedAt, a.ID,
	)
	return err
}

// DeleteAsset deletes an asset by ID.
func (s *AssetService) DeleteAsset(id string) error {
	_, err := s.db.Exec("DELETE FROM assets WHERE id = ?", id)
	return err
}
