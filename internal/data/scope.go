package data

import (
	"log"
	"net"
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
