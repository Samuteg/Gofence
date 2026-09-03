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
	Use:   "scope <workspace-id|name> <cidr>",
	Short: "Add CIDR to workspace scope",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := openDB()
		if err != nil {
			return err
		}
		defer db.Close()

		wsID, err := resolveWorkspaceID(db, args[0])
		if err != nil {
			return err
		}
		if err := db.ScopeAdd(wsID, args[1], "allowed"); err != nil {
			return err
		}
		fmt.Printf("Scope added: workspace=%d cidr=%s\n", wsID, args[1])
		return nil
	},
}

var workspaceSetActive = &cobra.Command{
	Use:   "set-active <nome>",
	Short: "Mark a workspace as the active one for scans",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := openDB()
		if err != nil {
			return err
		}
		defer db.Close()
		if _, err := db.WorkspaceByName(args[0]); err != nil {
			return fmt.Errorf("workspace not found: %s", args[0])
		}
		if err := db.KVSet("active_workspace", args[0]); err != nil {
			return err
		}
		fmt.Printf("Active workspace set to: %s\n", args[0])
		return nil
	},
}

func resolveWorkspaceID(db *data.DB, ref string) (int64, error) {
	var id int64
	if _, err := fmt.Sscanf(ref, "%d", &id); err == nil && id > 0 {
		return id, nil
	}
	return db.WorkspaceByName(ref)
}

func openDB() (*data.DB, error) {
	path := dbPath
	if path == "" {
		path = config.Get().DBPath
	}
	return data.New(path)
}

var workspaceDelete = &cobra.Command{
	Use:   "delete <workspace-id|nome>",
	Short: "Soft-delete a workspace (keeps history for auditing)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := openDB()
		if err != nil {
			return err
		}
		defer db.Close()

		wsID, err := resolveWorkspaceID(db, args[0])
		if err != nil {
			return fmt.Errorf("workspace not found: %s", args[0])
		}
		if err := db.WorkspaceDelete(wsID); err != nil {
			return err
		}
		fmt.Printf("Workspace deleted: id=%d\n", wsID)
		return nil
	},
}

func init() {
	workspaceCmd.AddCommand(workspaceNew, workspaceList, workspaceScope, workspaceSetActive, workspaceDelete)
	rootCmd.AddCommand(workspaceCmd)
}
