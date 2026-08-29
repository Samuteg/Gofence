package cmd

import (
	"fmt"

	"github.com/nixteg/gofence/internal/config"
	"github.com/nixteg/gofence/internal/data"
	"github.com/spf13/cobra"
)

var workspaceCmd = &cobra.Command{
	Use:   "workspace",
	Short: "Manage workspaces and scope",
}

var workspaceNew = &cobra.Command{
	Use:   "new <nome>",
	Short: "Create new workspace",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := openDB()
		if err != nil {
			return err
		}
		defer db.Close()

		id, err := db.WorkspaceCreate(args[0])
		if err != nil {
			return err
		}
		fmt.Printf("Workspace created: id=%d name=%s\n", id, args[0])
		return nil
	},
}

var workspaceList = &cobra.Command{
	Use:   "list",
	Short: "List workspaces",
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := openDB()
		if err != nil {
			return err
		}
		defer db.Close()

		ws, err := db.WorkspaceList()
		if err != nil {
			return err
		}
		for _, w := range ws {
			fmt.Printf("id=%d name=%s created=%v\n", w.ID, w.Name, w.CreatedAt)
		}
		return nil
	},
}

var workspaceScope = &cobra.Command{
	Use:   "scope <workspace-id> <cidr>",
	Short: "Add CIDR to workspace scope",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := openDB()
		if err != nil {
			return err
		}
		defer db.Close()

		var wsID int64
		fmt.Sscanf(args[0], "%d", &wsID)
		if err := db.ScopeAdd(wsID, args[1], "allowed"); err != nil {
			return err
		}
		fmt.Printf("Scope added: workspace=%d cidr=%s\n", wsID, args[1])
		return nil
	},
}

func openDB() (*data.DB, error) {
	cfg := config.Get()
	return data.New(cfg.DBPath)
}

func init() {
	workspaceCmd.AddCommand(workspaceNew, workspaceList, workspaceScope)
	rootCmd.AddCommand(workspaceCmd)
}
