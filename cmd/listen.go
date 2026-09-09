package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/nixteg/gofence/internal/exploit"
	"github.com/nixteg/gofence/internal/ux"
	"github.com/spf13/cobra"
)

var listenProtocol string

var listenCmd = &cobra.Command{
	Use:   "listen [porta]",
	Short: "Multi-handler for reverse connections (interactive: sessions, send <id> <cmd>, kill <id>)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Porta: valida de verdade em vez de engolir erro de parse.
		port := 4444
		if len(args) > 0 {
			p, err := strconv.Atoi(strings.TrimSpace(args[0]))
			if err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("invalid port %q: must be 1-65535", args[0])
			}
			port = p
		}

		handler := exploit.NewMultiHandler(listenProtocol, port)

		// SIGINT/SIGTERM encerram o listener graciosamente (fecha sessões).
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigCh
			fmt.Fprintln(os.Stderr, "\nshutting down listener...")
			handler.Close()
			os.Exit(0)
		}()

		// Loop interativo: status/sessions, send <id> <cmd>, kill <id>.
		// Só é ativado quando stdin é um terminal; em pipe, o handler roda
		// puro (modo servidor).
		go func() {
			if !ux.IsTTY(os.Stdin) {
				return
			}
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				handleListenCommand(handler, scanner.Text())
			}
		}()

		if err := handler.Listen(); err != nil {
			return err
		}
		return nil
	},
}

// handleListenCommand processa um comando digitado no console do listener.
func handleListenCommand(handler *exploit.MultiHandler, line string) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return
	}
	switch fields[0] {
	case "sessions", "status":
		sessions := handler.GetSessions()
		fmt.Fprintf(os.Stderr, "active sessions: %d\n", len(sessions))
		for _, s := range sessions {
			remote := "<unknown>"
			if s.Conn != nil {
				if addr := s.Conn.RemoteAddr(); addr != nil {
					remote = addr.String()
				}
			}
			fmt.Fprintf(os.Stderr, "  #%d %s\n", s.ID, remote)
		}
	case "send":
		if len(fields) < 3 {
			fmt.Fprintln(os.Stderr, "usage: send <session-id> <data...>")
			return
		}
		id, err := strconv.Atoi(fields[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid session id %q\n", fields[1])
			return
		}
		data := strings.Join(fields[2:], " ") + "\n"
		if err := handler.SendToSession(id, data); err != nil {
			fmt.Fprintf(os.Stderr, "send: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "sent to session %d\n", id)
		}
	case "kill":
		if len(fields) < 2 {
			fmt.Fprintln(os.Stderr, "usage: kill <session-id>")
			return
		}
		id, err := strconv.Atoi(fields[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid session id %q\n", fields[1])
			return
		}
		if err := handler.CloseSession(id); err != nil {
			fmt.Fprintf(os.Stderr, "kill: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "session %d closed\n", id)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (try: sessions | send <id> <cmd> | kill <id>)\n", fields[0])
	}
}

func init() {
	listenCmd.Flags().StringVar(&listenProtocol, "proto", "tcp", "tcp|udp")
	rootCmd.AddCommand(listenCmd)
}
