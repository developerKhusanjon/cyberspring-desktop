package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

var (
	globalDB    *sql.DB
	globalMu    sync.Mutex
	currentPath string
)

// InitDB initializes SQLite database at the specified path or standard user directory.
// Configures WAL mode, foreign keys, and busy timeout for durability and concurrency.
func InitDB(customPath string) (*sql.DB, string, error) {
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalDB != nil {
		return globalDB, currentPath, nil
	}

	dbPath := customPath
	if dbPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			homeDir = "."
		}
		appDir := filepath.Join(homeDir, ".riskguard")
		if err := os.MkdirAll(appDir, 0755); err != nil {
			return nil, "", fmt.Errorf("failed to create riskguard directory: %w", err)
		}
		dbPath = filepath.Join(appDir, "riskguard.db")
	}

	// SQLite connection string with PRAGMAs for durability and performance
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Bounded concurrency pool
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	if err := db.Ping(); err != nil {
		return nil, "", fmt.Errorf("failed to connect to database: %w", err)
	}

	// Run migrations
	if err := RunMigrations(db); err != nil {
		return nil, "", fmt.Errorf("database migrations failed: %w", err)
	}

	globalDB = db
	currentPath = dbPath
	return db, dbPath, nil
}

// GetDB returns the active database connection.
func GetDB() *sql.DB {
	globalMu.Lock()
	defer globalMu.Unlock()
	return globalDB
}

// GetDBPath returns the filesystem path of the current database.
func GetDBPath() string {
	globalMu.Lock()
	defer globalMu.Unlock()
	return currentPath
}

// BackupDatabase copies current database state safely to a target backup file.
func BackupDatabase(targetBackupPath string) error {
	globalMu.Lock()
	db := globalDB
	globalMu.Unlock()

	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	// SQLite VACUUM INTO creates a consistent online snapshot even during concurrent writes
	query := fmt.Sprintf("VACUUM INTO '%s'", targetBackupPath)
	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("online backup failed: %w", err)
	}
	return nil
}

// CloseDB gracefully closes the active database connection.
func CloseDB() error {
	globalMu.Lock()
	defer globalMu.Unlock()
	if globalDB != nil {
		err := globalDB.Close()
		globalDB = nil
		return err
	}
	return nil
}
