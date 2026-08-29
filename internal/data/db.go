package data

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	Conn *sql.DB
}

func New(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db := &DB{Conn: conn}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

func (db *DB) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS workspaces (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			deleted_at DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS scope (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			workspace_id INTEGER NOT NULL,
			cidr TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'allowed',
			FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
		)`,
		`CREATE TABLE IF NOT EXISTS hosts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			workspace_id INTEGER NOT NULL,
			ip TEXT NOT NULL,
			hostname TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
			UNIQUE(workspace_id, ip)
		)`,
		`CREATE TABLE IF NOT EXISTS ports (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			host_id INTEGER NOT NULL,
			port INTEGER NOT NULL,
			service TEXT,
			state TEXT NOT NULL DEFAULT 'open',
			FOREIGN KEY (host_id) REFERENCES hosts(id),
			UNIQUE(host_id, port)
		)`,
		`CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			host_id INTEGER NOT NULL,
			severity TEXT NOT NULL DEFAULT 'info',
			title TEXT NOT NULL,
			data TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (host_id) REFERENCES hosts(id)
		)`,
	}
	for _, q := range queries {
		if _, err := db.Conn.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) Close() error {
	return db.Conn.Close()
}

func (db *DB) WorkspaceCreate(name string) (int64, error) {
	res, err := db.Conn.Exec("INSERT INTO workspaces (name, created_at) VALUES (?, ?)", name, time.Now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) WorkspaceList() ([]Workspace, error) {
	rows, err := db.Conn.Query("SELECT id, name, created_at FROM workspaces WHERE deleted_at IS NULL")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ws []Workspace
	for rows.Next() {
		var w Workspace
		if err := rows.Scan(&w.ID, &w.Name, &w.CreatedAt); err != nil {
			return nil, err
		}
		ws = append(ws, w)
	}
	return ws, nil
}

func (db *DB) HostUpsert(workspaceID int64, ip, hostname string) (int64, error) {
	var id int64
	err := db.Conn.QueryRow(
		"INSERT INTO hosts (workspace_id, ip, hostname) VALUES (?, ?, ?) ON CONFLICT(workspace_id, ip) DO UPDATE SET hostname=excluded.hostname RETURNING id",
		workspaceID, ip, hostname,
	).Scan(&id)
	return id, err
}

func (db *DB) PortUpsert(hostID int64, port int, service, state string) error {
	_, err := db.Conn.Exec(
		"INSERT INTO ports (host_id, port, service, state) VALUES (?, ?, ?, ?) ON CONFLICT(host_id, port) DO UPDATE SET service=excluded.service, state=excluded.state",
		hostID, port, service, state,
	)
	return err
}

func (db *DB) FindingCreate(hostID int64, severity, title, data string) error {
	_, err := db.Conn.Exec(
		"INSERT INTO findings (host_id, severity, title, data) VALUES (?, ?, ?, ?)",
		hostID, severity, title, data,
	)
	return err
}

func (db *DB) ScopeAdd(workspaceID int64, cidr, scopeType string) error {
	_, err := db.Conn.Exec(
		"INSERT INTO scope (workspace_id, cidr, type) VALUES (?, ?, ?)",
		workspaceID, cidr, scopeType,
	)
	return err
}

func (db *DB) ScopeGetCIDRs(workspaceID int64) ([]string, error) {
	rows, err := db.Conn.Query("SELECT cidr FROM scope WHERE workspace_id = ? AND type = 'allowed'", workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cidrs []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		cidrs = append(cidrs, c)
	}
	return cidrs, nil
}

type Workspace struct {
	ID        int64
	Name      string
	CreatedAt time.Time
}
