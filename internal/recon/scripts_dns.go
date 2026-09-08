package recon

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

func init() {
	RegisterScript("dns", "resolver", func(host string, port int) ScriptResult {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
		r, _, err := c.ExchangeContext(ctx, m, fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			return ScriptResult{Service: "dns", Name: "resolver", OK: false, Detail: err.Error()}
		}
		if r.Rcode != dns.RcodeSuccess {
			return ScriptResult{Service: "dns", Name: "resolver", OK: false, Detail: fmt.Sprintf("rcode %d", r.Rcode)}
		}
		return ScriptResult{Service: "dns", Name: "resolver", OK: true, Detail: "responds to A query"}
	})
}