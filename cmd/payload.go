package cmd

import (
	"fmt"

	"github.com/nixteg/gofence/internal/exploit"
	"github.com/spf13/cobra"
)

var (
	payloadType string
	payloadIP   string
	payloadPort int
	payloadBind bool
)

var payloadCmd = &cobra.Command{
	Use:   "payload",
	Short: "Generate reverse/bind shell payloads",
	RunE: func(cmd *cobra.Command, args []string) error {
		pType, err := exploit.PayloadTypeFromString(payloadType)
		if err != nil {
			return err
		}
		payload, err := exploit.GeneratePayload(pType, payloadIP, payloadPort, payloadBind)
		if err != nil {
			return err
		}
		fmt.Println(payload)
		return nil
	},
}

func init() {
	payloadCmd.Flags().StringVar(&payloadType, "type", "nc", "nc|python|bash|perl|powershell")
	payloadCmd.Flags().StringVar(&payloadIP, "ip", "", "listener IP (LHOST)")
	payloadCmd.Flags().IntVar(&payloadPort, "port", 0, "listener port (LPORT)")
	payloadCmd.Flags().BoolVar(&payloadBind, "bind", false, "generate bind shell instead of reverse")
	rootCmd.AddCommand(payloadCmd)
}
