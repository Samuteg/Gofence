package cmd

import (
	"fmt"

	"github.com/nixteg/gofence/internal/exploit"
	"github.com/spf13/cobra"
)

var listenProtocol string

var listenCmd = &cobra.Command{
	Use:   "listen",
	Short: "Multi-handler for reverse connections",
	RunE: func(cmd *cobra.Command, args []string) error {
		port := 4444
		if len(args) > 0 {
			fmt.Sscanf(args[0], "%d", &port)
		}

		handler := exploit.NewMultiHandler(listenProtocol, port)
		if err := handler.Listen(); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	listenCmd.Flags().StringVar(&listenProtocol, "proto", "tcp", "tcp|udp")
	rootCmd.AddCommand(listenCmd)
}
