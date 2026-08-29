package data

type Host struct {
	ID          int64  `json:"id"`
	WorkspaceID int64  `json:"workspace_id"`
	IP          string `json:"ip"`
	Hostname    string `json:"hostname,omitempty"`
}

type Port struct {
	ID      int64  `json:"id"`
	HostID  int64  `json:"host_id"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	State   string `json:"state"`
}

type Finding struct {
	ID       int64  `json:"id"`
	HostID   int64  `json:"host_id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Data     string `json:"data,omitempty"`
}
