package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/eonedge/vulnscan/pkg/scanner"
)

// DB handles database operations
type DB struct {
	conn *sql.DB
}

// NewDB creates a new database connection
func NewDB(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create tables if they don't exist
	if err := initDB(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	return &DB{conn: conn}, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
}

// initDB initializes the database schema
func initDB(conn *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target TEXT NOT NULL,
			start_time DATETIME NOT NULL,
			end_time DATETIME,
			duration INTEGER,
			endpoints INTEGER,
			vulnerabilities INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS vulnerabilities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			type TEXT NOT NULL,
			severity TEXT NOT NULL,
			url TEXT NOT NULL,
			parameter TEXT,
			payload TEXT,
			description TEXT,
			evidence TEXT,
			timestamp DATETIME NOT NULL,
			FOREIGN KEY (scan_id) REFERENCES scans(id)
		)`,
		`CREATE TABLE IF NOT EXISTS endpoints (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			url TEXT NOT NULL,
			method TEXT NOT NULL,
			params TEXT,
			depth INTEGER,
			source TEXT,
			FOREIGN KEY (scan_id) REFERENCES scans(id)
		)`,
	}

	for _, query := range queries {
		if _, err := conn.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return nil
}

// SaveScan saves a scan result to the database
func (db *DB) SaveScan(result *scanner.ScanResult) (int64, error) {
	query := `INSERT INTO scans (target, start_time, end_time, duration, endpoints, vulnerabilities) 
			  VALUES (?, ?, ?, ?, ?, ?)`

	result2, err := db.conn.Exec(query,
		result.Target,
		result.StartTime,
		result.EndTime,
		result.Duration.Milliseconds(),
		result.Endpoints,
		len(result.Vulnerabilities),
	)
	if err != nil {
		return 0, fmt.Errorf("failed to insert scan: %w", err)
	}

	scanID, err := result2.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert ID: %w", err)
	}

	// Save vulnerabilities
	for _, vuln := range result.Vulnerabilities {
		if err := db.saveVulnerability(scanID, vuln); err != nil {
			return scanID, fmt.Errorf("failed to save vulnerability: %w", err)
		}
	}

	return scanID, nil
}

// saveVulnerability saves a vulnerability to the database
func (db *DB) saveVulnerability(scanID int64, vuln scanner.Vulnerability) error {
	query := `INSERT INTO vulnerabilities (scan_id, type, severity, url, parameter, payload, description, evidence, timestamp)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.conn.Exec(query,
		scanID,
		vuln.Type,
		vuln.Severity,
		vuln.URL,
		vuln.Parameter,
		vuln.Payload,
		vuln.Description,
		vuln.Evidence,
		vuln.Timestamp,
	)

	return err
}

// GetScan retrieves a scan by ID
func (db *DB) GetScan(scanID int64) (*scanner.ScanResult, error) {
	query := `SELECT target, start_time, end_time, duration, endpoints, vulnerabilities 
			  FROM scans WHERE id = ?`

	var result scanner.ScanResult
	var durationMs int64
	var vulnCount int

	err := db.conn.QueryRow(query, scanID).Scan(
		&result.Target,
		&result.StartTime,
		&result.EndTime,
		&durationMs,
		&result.Endpoints,
		&vulnCount,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan: %w", err)
	}

	result.Duration = time.Duration(durationMs) * time.Millisecond

	// Get vulnerabilities
	vulns, err := db.getVulnerabilities(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilities: %w", err)
	}
	result.Vulnerabilities = vulns

	return &result, nil
}

// getVulnerabilities retrieves all vulnerabilities for a scan
func (db *DB) getVulnerabilities(scanID int64) ([]scanner.Vulnerability, error) {
	query := `SELECT type, severity, url, parameter, payload, description, evidence, timestamp
			  FROM vulnerabilities WHERE scan_id = ?`

	rows, err := db.conn.Query(query, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities: %w", err)
	}
	defer rows.Close()

	var vulns []scanner.Vulnerability
	for rows.Next() {
		var vuln scanner.Vulnerability
		if err := rows.Scan(
			&vuln.Type,
			&vuln.Severity,
			&vuln.URL,
			&vuln.Parameter,
			&vuln.Payload,
			&vuln.Description,
			&vuln.Evidence,
			&vuln.Timestamp,
		); err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability: %w", err)
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// GetRecentScans retrieves recent scans
func (db *DB) GetRecentScans(limit int) ([]scanner.ScanResult, error) {
	query := `SELECT id, target, start_time, end_time, duration, endpoints, vulnerabilities 
			  FROM scans ORDER BY start_time DESC LIMIT ?`

	rows, err := db.conn.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query scans: %w", err)
	}
	defer rows.Close()

	var scans []scanner.ScanResult
	for rows.Next() {
		var scan scanner.ScanResult
		var scanID int64
		var durationMs int64
		var vulnCount int

		if err := rows.Scan(
			&scanID,
			&scan.Target,
			&scan.StartTime,
			&scan.EndTime,
			&durationMs,
			&scan.Endpoints,
			&vulnCount,
		); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		scan.Duration = time.Duration(durationMs) * time.Millisecond
		scans = append(scans, scan)
	}

	return scans, nil
}
