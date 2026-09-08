package recon

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

func init() {
	RegisterScript("smtp", "banner", func(host string, port int) ScriptResult {
		banner := bannerProbe(host, port, 2*time.Second)
		if banner == "" {
			return ScriptResult{Service: "smtp", Name: "banner", OK: false, Detail: "no banner"}
		}
		return ScriptResult{Service: "smtp", Name: "banner", OK: true, Detail: truncate(banner)}
	})

	RegisterScript("smtp", "ehlo", func(host string, port int) ScriptResult {
		addr := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			return ScriptResult{Service: "smtp", Name: "ehlo", OK: false, Detail: err.Error()}
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		reader := bufio.NewReader(conn)

		// Banner 220 inicial.
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "220") {
			return ScriptResult{Service: "smtp", Name: "ehlo", OK: false, Detail: "no 220 greeting"}
		}

		fmt.Fprintf(conn, "EHLO gofence.local\r\n")
		line, err = reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "250") {
			return ScriptResult{Service: "smtp", Name: "ehlo", OK: false, Detail: "EHLO not accepted"}
		}
		return ScriptResult{Service: "smtp", Name: "ehlo", OK: true, Detail: "EHLO accepted"}
	})
}