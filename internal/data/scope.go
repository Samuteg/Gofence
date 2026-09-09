package data

import (
	"log"
	"net"
	"net/url"
	"strings"
)

type ScopeGuard struct {
	allowedCIDRs []*net.IPNet
}

func NewScopeGuard(cidrs []string) *ScopeGuard {
	g := &ScopeGuard{}
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		g.allowedCIDRs = append(g.allowedCIDRs, ipNet)
	}
	return g
}

// Empty reports whether the guard has no CIDRs (blocks everything).
func (g *ScopeGuard) Empty() bool {
	return g == nil || len(g.allowedCIDRs) == 0
}

func (g *ScopeGuard) IsAllowed(ip net.IP) bool {
	for _, cidr := range g.allowedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (g *ScopeGuard) CheckAndLog(ip net.IP, action string) bool {
	if g.IsAllowed(ip) {
		return true
	}
	log.Printf("[SCOPE] Out-of-Scope Blocked: %s attempted %s\n", ip.String(), action)
	return false
}

// GuardForWorkspace builds a ScopeGuard from the workspace's allowed CIDRs.
// An empty scope yields a guard that blocks everything (fail-closed).
func GuardForWorkspace(db *DB, workspaceID int64) (*ScopeGuard, error) {
	cidrs, err := db.ScopeGetCIDRs(workspaceID)
	if err != nil {
		return nil, err
	}
	return NewScopeGuard(cidrs), nil
}

// CheckHost reports whether host is in scope. Host may be an IP, ip:port,
// URL or bare hostname (resolved via ResolveIP). Anything unresolvable or
// empty is blocked: without an IP there is no way to prove it is contracted
// (fail-closed). A nil guard also blocks.
func CheckHost(g *ScopeGuard, host, action string) bool {
	ip := hostToIP(host)
	if ip == nil || g == nil {
		log.Printf("[SCOPE] Out-of-Scope Blocked: %s attempted %s (unresolvable)\n", host, action)
		return false
	}
	return g.CheckAndLog(ip, action)
}

// FilterAllowed keeps only the hosts in scope, logging each blocked one.
func FilterAllowed(g *ScopeGuard, hosts []string, action string) []string {
	var out []string
	for _, h := range hosts {
		if CheckHost(g, h, action) {
			out = append(out, h)
		}
	}
	return out
}

// HostOf extrai host[:porta] de um alvo que pode ser URL, host:porta,
// CIDR ou host nu. Canonical para formatting/scoping em todo o CLI.
func HostOf(target string) string {
	host := strings.TrimSpace(target)
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil && u.Host != "" {
			return u.Host
		}
	}
	if ip, _, err := net.ParseCIDR(host); err == nil {
		return ip.String()
	}
	// Preserve colchetes IPv6 removal: host:porta sem esquema.
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(host, "[]")
}

func hostToIP(host string) net.IP {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil && u.Host != "" {
			host = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if ip, _, err := net.ParseCIDR(host); err == nil {
		return ip
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	if resolved := ResolveIP(host); resolved != "" {
		return net.ParseIP(resolved)
	}
	return nil
}
