package data

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// ipCache memoiza resoluções DNS dentro do processo: loops de persistência
// chamam ResolveIP por finding, e sem cache cada finding viraria uma query.
var ipCache sync.Map // host -> ip string

// ResolveIP returns the first IPv4 for host, best-effort (empty on failure).
// Resultados são memoizados por host (inclusive falhas) por processo.
func ResolveIP(host string) string {
	host = stripPort(host)
	if v, ok := ipCache.Load(host); ok {
		return v.(string)
	}
	ip := lookupIP(host)
	ipCache.Store(host, ip)
	return ip
}

func lookupIP(host string) string {
	ips, err := net.LookupIP(host)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	if len(ips) > 0 {
		return ips[0].String()
	}
	return ""
}

// ResetIPCache limpa o cache de resoluções (útil em testes e scans longos
// que duram mais que o TTL do DNS).
func ResetIPCache() {
	ipCache.Range(func(k, _ interface{}) bool {
		ipCache.Delete(k)
		return true
	})
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

type DB struct {
	Conn *sql.DB
}

func New(dbPath string) (*DB, error) {
	if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}
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
		`CREATE TABLE IF NOT EXISTS kv (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
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

// WorkspaceDelete soft-deletes the workspace, keeping rows for auditing.
// It clears the active-workspace marker when it references the deleted one.
func (db *DB) WorkspaceDelete(id int64) error {
	res, err := db.Conn.Exec(
		"UPDATE workspaces SET deleted_at = CURRENT_TIMESTAMP WHERE id = ? AND deleted_at IS NULL",
		id,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("workspace not found: id=%d", id)
	}
	var name string
	if err := db.Conn.QueryRow("SELECT name FROM workspaces WHERE id = ?", id).Scan(&name); err == nil {
		if active, _ := db.KVGet("active_workspace"); active == name {
			_, _ = db.Conn.Exec("DELETE FROM kv WHERE key = 'active_workspace'")
		}
	}
	return nil
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
	// Validação na entrada: CIDR inválido seria silenciosamente ignorado pelo
	// ScopeGuard depois (fail-closed), mas o operador merece o erro agora.
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
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

func (db *DB) KVGet(key string) (string, error) {
	var v string
	err := db.Conn.QueryRow("SELECT value FROM kv WHERE key = ?", key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (db *DB) KVSet(key, value string) error {
	_, err := db.Conn.Exec(
		"INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
		key, value,
	)
	return err
}

func (db *DB) WorkspaceByName(name string) (int64, error) {
	var id int64
	err := db.Conn.QueryRow("SELECT id FROM workspaces WHERE name = ? AND deleted_at IS NULL", name).Scan(&id)
	return id, err
}

// ActiveWorkspace resolves the workspace to persist findings into. An explicit
// name wins; otherwise the active workspace stored via KVSet("active_workspace").
func (db *DB) ActiveWorkspace(name string) (int64, error) {
	if name != "" {
		return db.WorkspaceByName(name)
	}
	active, _ := db.KVGet("active_workspace")
	if active == "" {
		return 0, fmt.Errorf("no active workspace; pass --workspace <name> or run 'gofence workspace set-active <name>'")
	}
	return db.WorkspaceByName(active)
}

func (db *DB) Hosts(workspaceID int64) ([]Host, error) {
	rows, err := db.Conn.Query("SELECT id, workspace_id, ip, hostname FROM hosts WHERE workspace_id = ? ORDER BY ip", workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hosts []Host
	for rows.Next() {
		var h Host
		if err := rows.Scan(&h.ID, &h.WorkspaceID, &h.IP, &h.Hostname); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

func (db *DB) Ports(hostID int64) ([]Port, error) {
	rows, err := db.Conn.Query("SELECT id, host_id, port, service, state FROM ports WHERE host_id = ? ORDER BY port", hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ports []Port
	for rows.Next() {
		var p Port
		if err := rows.Scan(&p.ID, &p.HostID, &p.Port, &p.Service, &p.State); err != nil {
			return nil, err
		}
		ports = append(ports, p)
	}
	return ports, nil
}

func (db *DB) Findings(workspaceID int64) ([]Finding, error) {
	rows, err := db.Conn.Query(
		"SELECT f.id, f.host_id, f.severity, f.title, f.data FROM findings f JOIN hosts h ON h.id = f.host_id WHERE h.workspace_id = ? ORDER BY f.severity, f.id",
		workspaceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.HostID, &f.Severity, &f.Title, &f.Data); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func (db *DB) SaveFinding(workspaceID int64, ip, hostname, severity, title, data string) error {
	hostID, err := db.HostUpsert(workspaceID, ip, hostname)
	if err != nil {
		return err
	}
	return db.FindingCreate(hostID, severity, title, data)
}
