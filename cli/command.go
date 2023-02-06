package cli

import (
	"context"
	"fmt"
	"log"

	"github.com/kvesta/vesta/config"
	"github.com/kvesta/vesta/pkg/vulnlib"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "vesta [OPTIONS]",
		Short: "Docker and Kubernetes analysis",
		Long: `Vesta is a static analysis of vulnerabilities, Docker and Kubernetes configuration detect toolkit
               Tutorial is available at https://github.com/kvesta/vesta`,
	}

	tarFile    string
	nameSpace  string
	kubeconfig string
	outfile    string
	updateall  bool
	skipUpdate bool
	inside     bool
)

func Execute() error {

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information and qui",
		Args:  NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(versions)
		},
	}

	// Upgrade vulnerability database
	dataupgradeCmd := &cobra.Command{
		Use:   "update",
		Short: "Update vulnerability database",
		Args:  NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			ctx := config.Ctx
			ctx = context.WithValue(ctx, "reset", updateall)

			err := vulnlib.Fetch(ctx)
			if err != nil {
				log.Printf("Updating vulnerability database failed, error: %v", err)
			}

			log.Printf(config.Green("Updating vulnerability database success"))
		},
	}

	dataupgradeCmd.Flags().BoolVarP(&updateall, "all", "a", false, "Reset the database")

	rootCmd.AddCommand(dataupgradeCmd)
	rootCmd.AddCommand(versionCmd)

	analyze()
	scan()

	return rootCmd.Execute()
}
