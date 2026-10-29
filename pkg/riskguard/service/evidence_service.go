package service

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"cyberspring/pkg/riskguard/models"
)

// EvidenceService handles secure evidence upload, SHA-256 integrity hashing, and storage.
type EvidenceService struct {
	db       *sql.DB
	basePath string
}

// NewEvidenceService creates an EvidenceService.
func NewEvidenceService(db *sql.DB) *EvidenceService {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dir := filepath.Join(home, ".riskguard", "evidence")
	_ = os.MkdirAll(dir, 0755)

	return &EvidenceService{
		db:       db,
		basePath: dir,
	}
}

// SaveEvidence validates, hashes, and stores an evidence document.
func (s *EvidenceService) SaveEvidence(title, description, fileName, mimeType, entityType, entityID, uploader string, content []byte) (*models.Evidence, error) {
	// Calculate SHA-256 hash
	hasher := sha256.New()
	hasher.Write(content)
	hashHex := hex.EncodeToString(hasher.Sum(nil))

	id := fmt.Sprintf("ev_%d", time.Now().UnixNano())
	safeFileName := fmt.Sprintf("%s_%s", id, filepath.Base(fileName))
	destPath := filepath.Join(s.basePath, safeFileName)

	if err := os.WriteFile(destPath, content, 0644); err != nil {
		return nil, fmt.Errorf("failed to save evidence file: %w", err)
	}

	ev := &models.Evidence{
		ID:          id,
		Title:       title,
		Description: description,
		FileName:    fileName,
		FilePath:    destPath,
		FileSize:    int64(len(content)),
		MimeType:    mimeType,
		SHA256Hash:  hashHex,
		EntityType:  entityType,
		EntityID:    entityID,
		UploadedBy:  uploader,
		CreatedAt:   time.Now().Format("2006-01-02 15:04:05"),
	}

	_, err := s.db.Exec(`
		INSERT INTO evidence 
		(id, title, description, file_name, file_path, file_size, mime_type, sha256_hash, entity_type, entity_id, uploaded_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		ev.ID, ev.Title, ev.Description, ev.FileName, ev.FilePath, ev.FileSize,
		ev.MimeType, ev.SHA256Hash, ev.EntityType, ev.EntityID, ev.UploadedBy, ev.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return ev, nil
}

// ListEvidence lists evidence linked to an entity or all evidence.
func (s *EvidenceService) ListEvidence(entityType, entityID string) ([]models.Evidence, error) {
	querySQL := `
		SELECT id, title, description, file_name, file_path, file_size, mime_type, sha256_hash, entity_type, entity_id, uploaded_by, created_at
		FROM evidence
	`
	var args []interface{}
	if entityType != "" && entityID != "" {
		querySQL += " WHERE entity_type = ? AND entity_id = ?"
		args = append(args, entityType, entityID)
	}
	querySQL += " ORDER BY created_at DESC"

	rows, err := s.db.Query(querySQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.Evidence
	for rows.Next() {
		var ev models.Evidence
		err := rows.Scan(
			&ev.ID, &ev.Title, &ev.Description, &ev.FileName, &ev.FilePath, &ev.FileSize,
			&ev.MimeType, &ev.SHA256Hash, &ev.EntityType, &ev.EntityID, &ev.UploadedBy, &ev.CreatedAt,
		)
		if err == nil {
			results = append(results, ev)
		}
	}
	return results, nil
}

// VerifyIntegrity verifies that an evidence file has not been altered on disk.
func (s *EvidenceService) VerifyIntegrity(id string) (bool, error) {
	var filePath, expectedHash string
	err := s.db.QueryRow("SELECT file_path, sha256_hash FROM evidence WHERE id = ?", id).Scan(&filePath, &expectedHash)
	if err != nil {
		return false, err
	}

	f, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return false, err
	}

	actualHash := hex.EncodeToString(hasher.Sum(nil))
	return actualHash == expectedHash, nil
}
