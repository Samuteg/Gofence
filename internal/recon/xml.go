package recon

import (
	"encoding/xml"
	"os"
	"time"
)

// Estruturas no formato nmap -oX (subconjunto): nmaprun > host > address +
// ports > port > state/service.

type nmapRunXML struct {
	XMLName    xml.Name     `xml:"nmaprun"`
	Scanner    string       `xml:"scanner,attr"`
	StartStr   string       `xml:"startstr,attr"`
	Version    string       `xml:"version,attr"`
	Hosts      []hostXML    `xml:"host"`
}

type hostXML struct {
	StartTime string     `xml:"starttime,attr,omitempty"`
	EndTime   string     `xml:"endtime,attr,omitempty"`
	Address   addressXML `xml:"address"`
	Ports     portsXML   `xml:"ports"`
}

type addressXML struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type portsXML struct {
	Ports []portXML `xml:"port"`
}

type portXML struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    stateXML    `xml:"state"`
	Service  *serviceXML `xml:"service,omitempty"`
}

type stateXML struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr,omitempty"`
}

type serviceXML struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr,omitempty"`
	Version string `xml:"version,attr,omitempty"`
}

// WriteNmapXML serializa os resultados no formato -oX do nmap, agrupando por
// host. Campos não preenchidos ficam omitidos (DTD do nmap não exige tudo).
func WriteNmapXML(path string, results []PortResult) error {
	byHost := map[string][]PortResult{}
	var order []string
	for _, r := range results {
		h := r.Host
		if h == "" {
			h = "unknown"
		}
		if _, ok := byHost[h]; !ok {
			order = append(order, h)
		}
		byHost[h] = append(byHost[h], r)
	}

	now := time.Now().Format("Mon Jan  2 15:04:05 2006")
	run := nmapRunXML{Scanner: "gofence", StartStr: now, Version: "1.0"}
	for _, h := range order {
		host := hostXML{
			StartTime: time.Now().Format("2006-01-02 15:04:05"),
			EndTime:   time.Now().Format("2006-01-02 15:04:05"),
			Address:   addressXML{Addr: h, AddrType: "ipv4"},
		}
		for _, r := range byHost[h] {
			state := stateXML{State: r.State}
			var svc *serviceXML
			if r.Service != "" || r.Version != "" {
				svc = &serviceXML{Name: r.Service, Version: r.Version}
			}
			host.Ports.Ports = append(host.Ports.Ports, portXML{
				Protocol: "tcp",
				PortID:   r.Port,
				State:    state,
				Service:  svc,
			})
		}
		run.Hosts = append(run.Hosts, host)
	}

	out, err := xml.MarshalIndent(run, "", "  ")
	if err != nil {
		return err
	}
	// Cabeçalho + declaração no estilo do nmap.
	content := xml.Header + string(out) + "\n"
	return os.WriteFile(path, []byte(content), 0644)
}